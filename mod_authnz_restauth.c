/* This file is licensed under the Apache License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This file was written/modified by:
 * Mihai Ghete <viper@fsinf.at>
 * David Kaufmann <astra@fsinf.at>
 *
 */

#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "http_protocol.h"

#include "mod_auth.h"

#include <curl/curl.h> /* muhaha */

#ifndef NO_MEMCACHED
#include <libmemcached/memcached.h>
#include <openssl/sha.h>
#endif

/* configuration parameters */

#define APACHE_OLDER_THAN(major,minor) (AP_SERVER_MAJORVERSION_NUMBER < major) || (AP_SERVER_MAJORVERSION_NUMBER == major && AP_SERVER_MINORVERSION_NUMBER < minor)

typedef struct {
    char *url;
    CURL *session;
    int forward_ip;
    char *service_user;
    char *service_password;
    int service_validate_cert;
#ifndef NO_MEMCACHED    
	memcached_st *cache;
	int cache_expiry;
#endif
} authnz_restauth_config;

#if !(APACHE_OLDER_THAN(2,4))
static APR_OPTIONAL_FN_TYPE(ap_authn_cache_store) *authn_cache_store = NULL;
#define AUTHN_CACHE_STORE(r,user,realm,data) \
    if (authn_cache_store != NULL) \
        authn_cache_store((r), "restauth", (user), (realm), (data))
#endif

#ifndef NO_MEMCACHED
static void restauth_cache_error(request_rec *r, const char *command, memcached_st *cache, memcached_return cache_status) {
	char commandname[50];

	if (cache_status == MEMCACHED_SUCCESS) {
		strncpy(commandname, "MEMCACHED_SUCCESS", 49);
	} else if (cache_status == MEMCACHED_PROTOCOL_ERROR) {
		strncpy(commandname, "MEMCACHED_PROTOCOL_ERROR", 49);
	} else if (cache_status == MEMCACHED_DATA_EXISTS) {
		strncpy(commandname, "MEMCACHED_DATA_EXISTS", 49);
	} else if (cache_status == MEMCACHED_DATA_DOES_NOT_EXIST) {
		strncpy(commandname, "MEMCACHED_DATA_DOES_NOT_EXIST", 49);
	} else if (cache_status == MEMCACHED_NOTSTORED) {
		strncpy(commandname, "MEMCACHED_NOTSTORED", 49);
	} else if (cache_status == MEMCACHED_STORED) {
		strncpy(commandname, "MEMCACHED_STORED", 49);
	} else if (cache_status == MEMCACHED_NOTFOUND) {
		strncpy(commandname, "MEMCACHED_NOTFOUND", 49);
	} else if (cache_status == MEMCACHED_ERRNO) {
		strncpy(commandname, "MEMCACHED_ERRNO", 49);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "Memcached response: %s", memcached_strerror(cache, cache_status));
	} else {
		strncpy(commandname, "COMMAND_NOT_FOUND", 49);
	}
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "RestAuth cache failed on request: %s [Status: %d (%s)]", command, cache_status, commandname);
}
#endif

static apr_status_t restauth_cleanup(void *data) {
    authnz_restauth_config *conf = (authnz_restauth_config *)data;

    if (conf->session) {
        curl_easy_cleanup(conf->session);
        conf->session = NULL;
    }

#ifndef NO_MEMCACHED
   if (conf->cache) {
       memcached_free (conf->cache);
       conf->cache = NULL;
   }
#endif

    return 0;
}

static void *create_authnz_restauth_dir_config(apr_pool_t *p, char *d)
{
    authnz_restauth_config *conf = apr_palloc(p, sizeof(*conf));
    conf->url = NULL;
    conf->session = NULL;
    conf->forward_ip = 0;

    conf->service_user = NULL;
    conf->service_password = NULL;
    conf->service_validate_cert = 1;

#ifndef NO_MEMCACHED
	conf->cache = NULL;
	conf->cache_expiry = 300;
#endif

    /* register cleanup handler */
    apr_pool_cleanup_register(p, conf, restauth_cleanup, restauth_cleanup);

    return conf;
}

static const char *restauth_set_locator(cmd_parms *cmd,
                                   void *conf_data, const char *arg)
{
    if (!*arg || !ap_is_url(arg))
        return "URL not specified";

    /* init url */
    authnz_restauth_config *conf = (authnz_restauth_config *)conf_data;
    conf->url = apr_psprintf(cmd->pool, "%s%s", arg,
			     /* add trailing slash if omitted */
			     (arg[strlen(arg)-1] == '/')?"":"/");

    /* init CURL session if not already initialized */
    if (!conf->session) {
        conf->session = curl_easy_init();
        if (!conf->session)
            return "Could not initialize HTTP request library";
    }

    return NULL;
}

#ifndef NO_MEMCACHED
static const char *restauth_set_cache(cmd_parms *cmd,
									void *conf_data, const char *arg)
{
	if (!*arg) {
		return "Address not specified";
	}

	authnz_restauth_config *conf = (authnz_restauth_config *)conf_data;

	/* init memcached session if not already initialized */
    if (!conf->cache) {
        memcached_return rv;
        conf->cache = memcached_create(NULL);
        if (!conf->cache) {
          return "Could not create memcache struct!";
        }
    }

	/* add memcached host */
	if (conf->cache) {
		char *host;
		int port;
		int res;
		if ((host = malloc(128)) == NULL) {
			return "Could not allocate memory for host";
		}
		if ((res = sscanf(arg, "%127[^:]:%u", host, &port)) != 2){
			return apr_psprintf(cmd->pool, "Could not parse host \"%s\" (%i parsed: host: %s port: %i)", arg, res, host, port);
		}
        memcached_return rv;
        rv = memcached_server_add(conf->cache, host, port);
        if (rv != MEMCACHED_SUCCESS) {
            restauth_cache_error(NULL, "add_server", conf->cache, rv);
	    }
		free(host);
	}

	return NULL;
}
#endif

static const command_rec authnz_restauth_cmds[] =
{
    /* for now, the one protocol implemented is:
       - RestAuth-POST: POST AuthURL/users/<user>/ (with password=<password> as www-urlencoded POST data)
                        GET AuthURL/groups/<group>/users/<user>/ to check if user is in a group ("Requires restauth-group")
     */
    AP_INIT_TAKE1("RestAuthAddress", restauth_set_locator, NULL, OR_AUTHCFG,
        "The URL of the authentication service"),

    AP_INIT_TAKE1("RestAuthServiceUser", ap_set_string_slot,
        (void *)APR_OFFSETOF(authnz_restauth_config, service_user), OR_AUTHCFG,
        "The username for the RestAuth service"),
    AP_INIT_TAKE1("RestAuthServicePassword", ap_set_string_slot,
        (void *)APR_OFFSETOF(authnz_restauth_config, service_password), OR_AUTHCFG,
        "The password for the RestAuth service"),

    AP_INIT_FLAG("RestAuthServiceValidateCertificate", ap_set_flag_slot,
        (void *)APR_OFFSETOF(authnz_restauth_config, service_validate_cert), OR_AUTHCFG,
        "Limited to 'on' or 'off'"),

    AP_INIT_FLAG("RestAuthForwardIP", ap_set_flag_slot,
        (void *)APR_OFFSETOF(authnz_restauth_config, forward_ip), OR_AUTHCFG,
        "Limited to 'on' or 'off'"),

#ifndef NO_MEMCACHED
    AP_INIT_ITERATE("RestAuthCacheAddress", restauth_set_cache, NULL, OR_AUTHCFG,
        "The address(es) of the memcached-server(s)"),
    AP_INIT_TAKE1("RestAuthCacheExpiry", ap_set_int_slot,
        (void *)APR_OFFSETOF(authnz_restauth_config, cache_expiry), OR_AUTHCFG,
        "Time in seconds after which memcached entries expire"),
#endif
    {NULL}
};

/* basic authentication handler */

/* utility function */
static char* url_pescape(apr_pool_t *p, const char *str)
{
    // allocate 3 times the size of str
    char *escaped = apr_palloc(p, strlen(str)*3+1);
    char *escaped_str = escaped;

    while (*str) {
        if ((*str >= 'a' && *str <= 'z') || (*str >= 'A' && *str <= 'Z') || (*str >= '0' && *str <= '9'))
            *escaped_str = *str;
        else if (*str == ' ')
            *escaped_str = '+';
        else {
            unsigned char str_val = (unsigned char)(*str);
            *escaped_str = '%';
            *(escaped_str+1) = ((str_val/16) < 10) ? ('0' + str_val/16) : ('A' - 10 + str_val/16);
            *(escaped_str+2) = ((str_val%16) < 10) ? ('0' + str_val%16) : ('A' - 10 + str_val%16);
            escaped_str += 2;
        }

        escaped_str++;
        str++;
    }
    *escaped_str = '\0';

    return escaped;
}

/* function to set the necessary curl options */
static void config_curl_session(CURL *session, char *url, char *post_data) {
  curl_easy_setopt(session, CURLOPT_NETRC, CURL_NETRC_IGNORED);
  curl_easy_setopt(session, CURLOPT_NOSIGNAL, 1L);

  if (post_data) {
    curl_easy_setopt(session, CURLOPT_POST, 1L);
    curl_easy_setopt(session, CURLOPT_POSTFIELDS, post_data);
  } else {
    curl_easy_setopt(session, CURLOPT_HTTPGET, 1L);
  }

  curl_easy_setopt(session, CURLOPT_URL, url);

}

/* function to set the curl authentication and certificate validation options */
static void config_curl_auth_validate(apr_pool_t *p, authnz_restauth_config *conf) {

    /* certificate validation */
    curl_easy_setopt(conf->session, CURLOPT_SSL_VERIFYPEER, conf->service_validate_cert);

    /* ignore if no username or password */
    if (!conf->service_user || !conf->service_password)
        return;

    curl_easy_setopt(conf->session, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

#if LIBCURL_VERSION_NUM >= 0x071301 /* CURL >= 7.19.1 */
    curl_easy_setopt(conf->session, CURLOPT_USERNAME, conf->service_user);
    curl_easy_setopt(conf->session, CURLOPT_PASSWORD, conf->service_password);
#else /* CURL < 7.19.1 - USERPWD option */
    curl_easy_setopt(conf->session, CURLOPT_USERPWD,
                     apr_psprintf(p, "%s:%s", conf->service_user, conf->service_password));
#endif
}

/* function to log an error */
static void restauth_server_error(request_rec *r, const char *url, int curl_status, int http_code, char *data) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                          "RestAuth server failed on request: %s [CURL status: %s, HTTP code: %d]", url, curl_easy_strerror(curl_status), http_code);
}

module AP_MODULE_DECLARE_DATA authnz_restauth_module;

static authn_status authn_restauth_check(request_rec *r, const char *user,
                                    const char *sent_pw)
{
    authnz_restauth_config *conf = ap_get_module_config(r->per_dir_config, &authnz_restauth_module);

    /* ignore if not configured */
    if (!conf->url)
        return AUTH_USER_NOT_FOUND;

#ifndef NO_MEMCACHED
	memcached_return rv;
	uint32_t flags = 0;
	size_t cachevalue_len = 20;
	char *cachevalue;
	char *cachekey_user;

	unsigned char pwhash[20];
	char *salt = "restauth/pass/";
	int saltlen = strlen(salt);
	unsigned char *full_unhashed_string;

	if (conf->cache) {
		/* check memcached for value, if found return it instead of querying auth server */
		cachekey_user = apr_psprintf(r->pool, "restauth/users/%s/", user);
		cachevalue = memcached_get(conf->cache, cachekey_user, strlen(cachekey_user), &cachevalue_len, &flags, &rv);
        if (rv != MEMCACHED_SUCCESS && rv != MEMCACHED_NOTFOUND) {
            restauth_cache_error(r, "get_user", conf->cache, rv);
	    }

		full_unhashed_string = apr_psprintf(r->pool, "%s%s", salt, sent_pw);
		SHA1(full_unhashed_string, strlen(full_unhashed_string), pwhash);
		int i;
		for (i = 1; i < 1000; i++) {
			full_unhashed_string = malloc(saltlen+20);
			memcpy(full_unhashed_string, salt, saltlen);
			memcpy(full_unhashed_string+saltlen, pwhash, 20);
			SHA1(full_unhashed_string, saltlen+20, pwhash);
			free(full_unhashed_string);
		}
		if (cachevalue != NULL) {
			if (memcmp(cachevalue, pwhash, 20) == 0) {
				free(cachevalue);
				/* saved password is correct */
				return AUTH_GRANTED;
			}
			free(cachevalue);
		}
	}
#endif

    /* create url and storage */
    char *url;

    /* fetch client ip */
#if APACHE_OLDER_THAN(2,4)
    char *ip = r->connection->remote_ip;
#else
    char *ip = r->useragent_ip; /* renamed in 2.4 https://httpd.apache.org/docs/2.4/developer/new_api_2_4.html */
#endif

    char *post_data = apr_psprintf(r->pool, "password=%s%s%s",
                                   url_pescape(r->pool, sent_pw),
				   /* ip data if requested */
				   (conf->forward_ip)?"&ip=":"",
                                   (conf->forward_ip)?url_pescape(r->pool, ip):"");

    url	= apr_psprintf(r->pool, "%susers/%s/", conf->url,
                       url_pescape(r->pool, user));

    config_curl_session(conf->session, url, post_data);
    config_curl_auth_validate(r->pool, conf);

    int curl_perform_status = 0;
    int curl_info_status = 0;
    long curl_http_code;
    /* get response code - 200 range OK, 404 NOT OK */
    curl_perform_status = curl_easy_perform(conf->session);
    curl_info_status = curl_easy_getinfo(conf->session, CURLINFO_RESPONSE_CODE, &curl_http_code);
    int curl_status = curl_perform_status + curl_info_status;

    /*ap_log_rerror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, r,
                      "REST auth URL request: %s", url);*/

    curl_easy_reset(conf->session);

    /* if status is not in the 200-299 range, return */
    if (curl_status != CURLE_OK || (curl_http_code > 299 || curl_http_code < 200)) {

        /* log a failed request / non-404 error code */
        if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404))
            restauth_server_error(r, url, curl_perform_status, curl_http_code, NULL);

        /* fail if request fails / returns internal server error */
        if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404))
            return AUTH_GENERAL_ERROR;

    	return AUTH_DENIED;
    }

#ifndef NO_MEMCACHED
	if (conf->cache) {
		time_t timer = time(NULL);
		rv = memcached_set (conf->cache, cachekey_user, strlen(cachekey_user), pwhash, 20, timer+(conf->cache_expiry), 0);
        if (rv != MEMCACHED_SUCCESS) {
            restauth_cache_error(r, "set_user", conf->cache, rv);
	    }
	}
#endif

#if !(APACHE_OLDER_THAN(2,4))
	AUTHN_CACHE_STORE(r, user, NULL, sent_pw);
#endif

    /* grant access */
    return AUTH_GRANTED;
}

/* Old constants, new constants... */
#if APACHE_OLDER_THAN(2,3)
#define RESTAUTH_AUTHZ_STATUS_TYPE int
#define RESTAUTH_AUTHZ_GRANTED OK
#define RESTAUTH_AUTHZ_DENIED HTTP_UNAUTHORIZED /* TODO: authoritive flag? */
#define RESTAUTH_AUTHZ_ERROR HTTP_INTERNAL_SERVER_ERROR
#else
#define RESTAUTH_AUTHZ_STATUS_TYPE authz_status
#define RESTAUTH_AUTHZ_GRANTED AUTHZ_GRANTED
#define RESTAUTH_AUTHZ_DENIED AUTHZ_DENIED
#define RESTAUTH_AUTHZ_ERROR AUTHZ_DENIED
#endif

static RESTAUTH_AUTHZ_STATUS_TYPE authz_restauth_check(request_rec *r, const char *group
#if !(APACHE_OLDER_THAN(2,4))
    , const void *parsed_args /* new API parameter, unused for now */
#endif
    ) {
    authnz_restauth_config *conf = ap_get_module_config(r->per_dir_config, &authnz_restauth_module);
    int curl_perform_status;
    int curl_info_status;
    int curl_status;
    long curl_http_code;

    /* assume user authenticated. check if user is in group */
    /* compile GET url/parameters */

    char *user = r->user;

    /* no user? shouldn't happen (except in 2.3.7-dev+)! */
    if (!user) {
#if APACHE_OLDER_THAN(2,4)
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "restauth-group: no user specified");
        return RESTAUTH_AUTHZ_ERROR;
#else
        /* apparently this is /modus operandi/ on 2.4 - calling this function twice, once with no user?
           special return value is required to call function again (group auth will fail otherwise) */
        return AUTHZ_DENIED_NO_USER;
#endif
    }

    /* user, but no url? */
    if (!conf->url) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "restauth-group authorization attempted with no RestAuthAddress specified");
        return RESTAUTH_AUTHZ_ERROR;
    }

#ifndef NO_MEMCACHED
	memcached_return rv;
	uint32_t flags = 0;
	size_t cachevalue_len = 3; // max password length
	char *cachevalue;
	char *cachekey_usergroup;

	if (conf->cache) {
		/* check memcached for value, if found return it instead of querying auth server */
		cachekey_usergroup = apr_psprintf (r->pool, "restauth/groups/%s/users/%s/", group, user);
		cachevalue = memcached_get (conf->cache, cachekey_usergroup, strlen(cachekey_usergroup), &cachevalue_len, &flags, &rv);
        if (rv != MEMCACHED_SUCCESS && rv != MEMCACHED_NOTFOUND) {
            restauth_cache_error(r, "get_group", conf->cache, rv);
	    }
		if (cachevalue != NULL) {
			if (strncmp(cachevalue, "yes", 3) == 0) {
				free(cachevalue);
				// user is in group
				return RESTAUTH_AUTHZ_GRANTED;
			}
			free(cachevalue);
		}
	}
#endif

    char *url = apr_psprintf(r->pool, "%sgroups/%s/users/%s/", conf->url,
                         url_pescape(r->pool, group),
                         url_pescape(r->pool, user));

    /* set request parameters */
    config_curl_session(conf->session, url, NULL);
    config_curl_auth_validate(r->pool, conf);

    /* get response code - 200-299 range OK, 404 NOT OK, 500 ERROR */
    curl_perform_status = curl_easy_perform(conf->session);
    curl_info_status = curl_easy_getinfo(conf->session, CURLINFO_RESPONSE_CODE, &curl_http_code);
    curl_status = curl_perform_status + curl_info_status;

    /* log a failed request / non-404 error code */
    if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404))
        restauth_server_error(r, url, curl_perform_status, curl_http_code, NULL);

    curl_easy_reset(conf->session);

    /* group exists, and user is in the specified group */
    if (curl_status == CURLE_OK && (curl_http_code <= 299 && curl_http_code >= 200))
	{
#ifndef NO_MEMCACHED
		if (conf->cache) {
			time_t timer = time(NULL);
			rv = memcached_set (conf->cache, cachekey_usergroup, strlen(cachekey_usergroup), "yes", 3, timer+(conf->cache_expiry), 0);
            if (rv != MEMCACHED_SUCCESS) {
                restauth_cache_error(r, "set_group", conf->cache, rv);
			}
		}
#endif
        return RESTAUTH_AUTHZ_GRANTED;
	}
    else if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404)) {
        /* fail if request fails / returns internal server error */
        return RESTAUTH_AUTHZ_ERROR;
    }
    else
        return RESTAUTH_AUTHZ_DENIED;
}

/* module stuff */

static const authn_provider authn_restauth_provider =
{
    &authn_restauth_check,
    NULL
};

#if APACHE_OLDER_THAN(2,3)
/* This wrapper is used by Apache versions <2.3 to filter out the
   first Require directive starting with "restauth-group". */
static int authz_restauth_provider_wrapper(request_rec *r) {

    /* loop through all the Requires directives... */
    const apr_array_header_t *reqs_arr = ap_requires(r);
    require_line *reqs;
    int i;
    int m = r->method_number;

    if (!reqs_arr)
        return DECLINED;

    reqs = (require_line *)reqs_arr->elts;
    for (i = 0; i < reqs_arr->nelts; i++) {
        const char *requirement;
        char *w;

        if (!(reqs[i].method_mask & (AP_METHOD_BIT << m)))
            continue;

        requirement = reqs[i].requirement;
        w = ap_getword_white(r->pool, &requirement);

        if (!strcasecmp(w, "restauth-group"))
            return authz_restauth_check(r, requirement);
    }

    return DECLINED;
}

#else
static const authz_provider authz_restauth_provider =
{
     &authz_restauth_check,
    NULL
};
#endif

#if !(APACHE_OLDER_THAN(2,4))
static void opt_retr(void)
{
    authn_cache_store = APR_RETRIEVE_OPTIONAL_FN(ap_authn_cache_store);
}
#endif

static void register_hooks(apr_pool_t *p)
{
#if APACHE_OLDER_THAN(2,3)

    /* <2.1 not supported! */
#if APACHE_OLDER_THAN(2,1)
#error "mod_authz_user not implemented before 2.1, support for earlier mechanism not implemented"
#endif

    static const char * const aszPost[]={ "mod_authz_user.c", NULL };

    /* register authn provider */
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "restauth", "0",
                         &authn_restauth_provider);

    /* perform "valid-user" and "user" (mod_authz_user.c) authorization first */
    ap_hook_auth_checker(&authz_restauth_provider_wrapper, NULL, aszPost, APR_HOOK_MIDDLE);

#else
    /* register authn provider */
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "restauth",
                              AUTHN_PROVIDER_VERSION,
                              &authn_restauth_provider, AP_AUTH_INTERNAL_PER_CONF);


    /* register authz provider */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "restauth-group",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_restauth_provider,
                              AP_AUTH_INTERNAL_PER_CONF);

    ap_hook_optional_fn_retrieve(opt_retr, NULL, NULL, APR_HOOK_MIDDLE);

#endif
}

#if APACHE_OLDER_THAN(2,3)
APLOG_USE_MODULE(authnz_restauth);
module AP_MODULE_DECLARE_DATA authnz_restauth_module =
#else
AP_DECLARE_MODULE(authnz_restauth) =
#endif
{
    STANDARD20_MODULE_STUFF,
    create_authnz_restauth_dir_config,  /* create config structure per directory */
    NULL,                         /* dir merger ensure strictness */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    authnz_restauth_cmds,               /* command apr_table_t */
    register_hooks                /* register hooks */
};
