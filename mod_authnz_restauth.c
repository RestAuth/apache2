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
#include <libmemcached/memcached.h>
#include <openssl/sha.h>

/* configuration parameters */

#define APACHE_OLDER_THAN(major,minor) (AP_SERVER_MAJORVERSION_NUMBER < major) || (AP_SERVER_MAJORVERSION_NUMBER == major && AP_SERVER_MINORVERSION_NUMBER < minor)

typedef struct {
    char *url;
    CURL *session;
    int forward_ip;
    char *service_user;
    char *service_password;
    int service_validate_cert;
	memcached_st *cache;
	int cacheexpiry;

} authnz_restauth_config;


static apr_status_t restauth_cleanup(void *data) {
    authnz_restauth_config *conf = (authnz_restauth_config *)data;

    if (conf->session) {
        curl_easy_cleanup(conf->session);
        conf->session = NULL;
    }

	if (conf->cache) {
		memcached_return rv;
		rv = memcached_flush (conf->cache, 0);
		memcached_free (conf->cache);
		conf->cache = NULL;
	}

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

	conf->cache = NULL;
	conf->cacheexpiry = 300;

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

	if (!conf->cache) {
		// const char *config_string= "--SERVER=localhost";
		// conf->cache = memcached (config_string, strlen(config_string));
		memcached_return rv;
		conf->cache = memcached_create(NULL);
		if (conf->cache == NULL) {
			return "Could not create memcache struct!";
		}
		rv = memcached_server_add(conf->cache, "localhost", 11211);
	}
    return NULL;
}

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

    AP_INIT_TAKE1("RestAuthCacheExpiry", ap_set_int_slot,
        (void *)APR_OFFSETOF(authnz_restauth_config, cacheexpiry), OR_AUTHCFG,
        "Time in seconds after which memcached-entries expire"),
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

	if (!conf->cache)
		return AUTH_USER_NOT_FOUND;

	/* check memcached for value, if found return it instead of querying auth server */
	memcached_return rv;
	uint32_t flags = 0;
	size_t cachevalue_len = 1024; // max password length
	char *cachevalue;
	char *cachekey_user = apr_psprintf (r->pool, "restauth/fsinf/users/%s/", user);
	cachevalue = memcached_get (conf->cache, cachekey_user, strlen(cachekey_user), &cachevalue_len, &flags, &rv);
	unsigned char pwhash[20];
	SHA1(sent_pw, strlen(sent_pw), pwhash);
	if (cachevalue != NULL) {
		if (strcmp(cachevalue, pwhash) == 0) {
			free(cachevalue);
			// saved password is correct
			return AUTH_GRANTED;
		}
		free(cachevalue);
	}

    /* create url and storage */
    char *url;

    /* fetch client ip */
    char *ip = r->connection->remote_ip;

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

	time_t timer = time(NULL);
	rv = memcached_set (conf->cache, cachekey_user, strlen(cachekey_user), pwhash, strlen(pwhash), timer+(conf->cacheexpiry), 0);

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

static RESTAUTH_AUTHZ_STATUS_TYPE authz_restauth_check(request_rec *r, const char *group) {
    authnz_restauth_config *conf = ap_get_module_config(r->per_dir_config, &authnz_restauth_module);
    int curl_perform_status;
    int curl_info_status;
    int curl_status;
    long curl_http_code;

    /* assume user authenticated. check if user is in group */
    /* compile GET url/parameters */

    char *user = r->user;

    /* no user? shouldn't happen! */
    if (!user)
        return RESTAUTH_AUTHZ_ERROR;

    /* user, but no url? */
    if (!conf->url) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "restauth-group authorization attempted with no RestAuthAddress specified");
        return RESTAUTH_AUTHZ_ERROR;
    }

	/* check memcached for value, if found return it instead of querying auth server */
	memcached_return rv;
	uint32_t flags = 0;
	size_t cachevalue_len = 3; // max password length
	char *cachevalue;
	char *cachekey_usergroup = apr_psprintf (r->pool, "restauth/fsinf/groups/%s/users/%s/", user, group);
	cachevalue = memcached_get (conf->cache, cachekey_usergroup, strlen(cachekey_usergroup), &cachevalue_len, &flags, &rv);
	if (cachevalue != NULL) {
		if (strncmp(cachevalue, "yes", 3) == 0) {
			free(cachevalue);
			// user is in group
			return RESTAUTH_AUTHZ_GRANTED;
		}
		free(cachevalue);
	}

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
		time_t timer = time(NULL);
		rv = memcached_set (conf->cache, cachekey_usergroup, strlen(cachekey_usergroup), "yes", 3, timer+(conf->cacheexpiry), 0);
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
};
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
