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

/* configuration parameters */

#define APACHE_OLDER_THAN(major,minor) (AP_SERVER_MAJORVERSION_NUMBER < major) || (AP_SERVER_MAJORVERSION_NUMBER == major && AP_SERVER_MINORVERSION_NUMBER < minor)

typedef struct {
    char *url;
    CURL *session;
    int forward_ip;
    char *group;
    char *service_user;
    char *service_password;

    char *cached_auth_header;
} authn_restauth_config;


static apr_status_t restauth_cleanup(void *data) {
    authn_restauth_config *conf = (authn_restauth_config *)data;

    if (conf->session) {
        curl_easy_cleanup(conf->session);
        conf->session = NULL;
    }

    return 0;
}

static void *create_authn_restauth_dir_config(apr_pool_t *p, char *d)
{
    authn_restauth_config *conf = apr_palloc(p, sizeof(*conf));
    conf->url = NULL;
    conf->session = NULL;
    conf->forward_ip = 0;
    conf->group = NULL;

    conf->service_user = NULL;
    conf->service_password = NULL;

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
    authn_restauth_config *conf = (authn_restauth_config *)conf_data;
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

static const command_rec authn_restauth_cmds[] =
{
    /* for now, the one protocol implemented is:
       - RestAuth-POST: POST AuthURL/users/<user>/ (with password=<password> as www-urlencoded POST data)
                        GET AuthURL/groups/<group>/users/<user>/ to check if user is in a group
     */
    AP_INIT_ITERATE("RestAuthAddress", restauth_set_locator, NULL, OR_AUTHCFG,
        "The URL of the authentication service"),
    AP_INIT_ITERATE("RestAuthGroup", ap_set_string_slot,
        (void *)APR_OFFSETOF(authn_restauth_config, group), OR_AUTHCFG, /* TODO: maybe use Require (authz) */
        "The group to be validated against"),

    AP_INIT_ITERATE("RestAuthServiceUser", ap_set_string_slot,
        (void *)APR_OFFSETOF(authn_restauth_config, service_user), OR_AUTHCFG,
        "The username for the RestAuth service"),
    AP_INIT_ITERATE("RestAuthServicePassword", ap_set_string_slot,
        (void *)APR_OFFSETOF(authn_restauth_config, service_password), OR_AUTHCFG,
        "The password for the RestAuth service"),

    AP_INIT_FLAG("RestAuthForwardIP", ap_set_flag_slot,
        (void *)APR_OFFSETOF(authn_restauth_config, forward_ip), OR_AUTHCFG,
        "Limited to 'on' or 'off'"),
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
            *escaped_str = '%';
            *(escaped_str+1) = ((*str/16) < 10) ? ('0' + *str/16) : ('A' - 10 + *str/16);
            *(escaped_str+2) = ((*str%16) < 10) ? ('0' + *str%16) : ('A' - 10 + *str%16);
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

/* function to set the curl authentication options */
static void config_curl_auth(apr_pool_t *p, authn_restauth_config *conf) {
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

module AP_MODULE_DECLARE_DATA authn_restauth_module;

static authn_status check_restauth(request_rec *r, const char *user,
                                    const char *sent_pw)
{
    authn_restauth_config *conf = ap_get_module_config(r->per_dir_config, &authn_restauth_module);

    /* ignore if not configured */
    if (!conf->url)
        return AUTH_USER_NOT_FOUND;

    /* create url and storage */
    apr_pool_t *url_pool = NULL;
    char *url;
    apr_pool_create(&url_pool, r->pool);

    /* fetch client ip */
    char *ip = r->connection->remote_ip;

    char *post_data = apr_psprintf(url_pool, "password=%s%s%s",
				   url_pescape(url_pool, sent_pw),
				   /* ip data if requested */
				   (conf->forward_ip)?"&ip=":"",
				   (conf->forward_ip)?url_pescape(url_pool, ip):"");

    url	= apr_psprintf(url_pool, "%susers/%s/", conf->url,
		       url_pescape(url_pool, user));

    config_curl_session(conf->session, url, post_data);
    config_curl_auth(url_pool, conf);

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

    	apr_pool_destroy(url_pool);

        /* fail if request fails / returns internal server error */
        if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404))
            return AUTH_GENERAL_ERROR;

    	return AUTH_DENIED;
    }

    /* if no group is set, grant access */
    if (!conf->group) {
    	apr_pool_destroy(url_pool);
	return AUTH_GRANTED;
    }

    /* user exists with valid password, now check if user is in group */
    /* compile GET url/parameters */

    url = apr_psprintf(url_pool, "%sgroups/%s/users/%s/", conf->url,
                         url_pescape(url_pool, conf->group),
                         url_pescape(url_pool, user));

    /* set request parameters */
    config_curl_session(conf->session, url, NULL);
    config_curl_auth(url_pool, conf);

    /* get response code - 200-299 range OK, 404 NOT OK, 500 ERROR */
    curl_perform_status = curl_easy_perform(conf->session);
    curl_info_status = curl_easy_getinfo(conf->session, CURLINFO_RESPONSE_CODE, &curl_http_code);
    curl_status = curl_perform_status + curl_info_status;

    /* log a failed request / non-404 error code */
    if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404))
        restauth_server_error(r, url, curl_perform_status, curl_http_code, NULL);

    apr_pool_destroy(url_pool);
    curl_easy_reset(conf->session);

    /* group exists, and user is in the specified group */
    if (curl_status == CURLE_OK && (curl_http_code <= 299 && curl_http_code >= 200))
    	return AUTH_GRANTED;
    else if (curl_status != CURLE_OK || (curl_http_code >= 400 && curl_http_code != 404)) {
        /* fail if request fails / returns internal server error */
        return AUTH_GENERAL_ERROR;
    }
    else
        return AUTH_DENIED;
}

/* module stuff */

static const authn_provider authn_restauth_provider =
{
    &check_restauth,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
#if APACHE_OLDER_THAN(2,3)
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "restauth", "0",
                         &authn_restauth_provider);
#else
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "restauth",
                              AUTHN_PROVIDER_VERSION,
                              &authn_restauth_provider, AP_AUTH_INTERNAL_PER_CONF);
#endif
}

#if APACHE_OLDER_THAN(2,3)
APLOG_USE_MODULE(authn_restauth);
module AP_MODULE_DECLARE_DATA authn_restauth_module =
#else
AP_DECLARE_MODULE(authn_restauth) =
#endif
{
    STANDARD20_MODULE_STUFF,
    create_authn_restauth_dir_config,  /* create config structure per directory */
    NULL,                         /* dir merger ensure strictness */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    authn_restauth_cmds,               /* command apr_table_t */
    register_hooks                /* register hooks */
};
