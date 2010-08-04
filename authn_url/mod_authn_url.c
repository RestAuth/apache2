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
 *
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

typedef struct {
    char *url;
    CURL *session;
    int use_post;
} authn_url_config;


static apr_status_t url_cleanup(void *data) {
    authn_url_config *conf = (authn_url_config *)data;

    if (conf->session) {
        curl_easy_cleanup(conf->session);
        conf->session = NULL;
    }

    return 0;
}

static void *create_authn_url_dir_config(apr_pool_t *p, char *d)
{
    authn_url_config *conf = apr_palloc(p, sizeof(*conf));
    conf->url = NULL;
    conf->session = NULL;
    conf->use_post = 1;

    /* register cleanup handler */
    apr_pool_cleanup_register(p, conf, url_cleanup, NULL);

    return conf;
}

static const char *url_set_locator(cmd_parms *cmd,
                                   void *conf_data, const char *arg)
{
    if (!*arg || !ap_is_url(arg))
        return "URL not specified";

    /* init url */
    authn_url_config *conf = (authn_url_config *)conf_data;
    conf->url = apr_pstrdup(cmd->pool, arg);

    /* init CURL session if not already initialized */
    if (!conf->session) {
        conf->session = curl_easy_init();
        if (!conf->session)
            return "Could not initialize HTTP request library";

        curl_easy_setopt(conf->session, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(conf->session, CURLOPT_NETRC, CURL_NETRC_IGNORED);

        curl_easy_setopt(conf->session, CURLOPT_FAILONERROR, 1L);
    }
    return NULL;
}

static const command_rec authn_url_cmds[] =
{
    /* for now, the two protocols implemented are:
       - RestAuth-GET: GET AuthURL?username=<user>&password=<password>
       - RestAuth-POST: POST AuthURL<user> (with password=<password> as www-urlencoded POST data)
     */
    AP_INIT_ITERATE("URLAuthAddress", url_set_locator, NULL, OR_AUTHCFG,
        "The URL of the authentication service"),
    AP_INIT_FLAG("URLAuthUsePost", ap_set_flag_slot,
        (void *)APR_OFFSETOF(authn_url_config, use_post), OR_AUTHCFG,
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

module AP_MODULE_DECLARE_DATA authn_url_module;

static authn_status check_url(request_rec *r, const char *user,
                                    const char *sent_pw)
{
    authn_url_config *conf = ap_get_module_config(r->per_dir_config, &authn_url_module);
    authn_status res = AUTH_USER_NOT_FOUND;

    /* ignore if not configured */
    if (!conf->url)
        return AUTH_USER_NOT_FOUND;

    /* check_url_mati begins here */

    /* create url */
    apr_pool_t *url_pool = NULL;
    char *url;
    apr_pool_create(&url_pool, r->pool);

    if (conf->use_post) {
        char *pw_data = apr_psprintf(url_pool, "password=%s",
                                     url_pescape(url_pool, sent_pw));

        curl_easy_setopt(conf->session, CURLOPT_POST, 1L);
        curl_easy_setopt(conf->session, CURLOPT_POSTFIELDS, pw_data);

        url = apr_psprintf(url_pool, "%s%s", conf->url, url_pescape(url_pool, user));
    }
    else {
        curl_easy_setopt(conf->session, CURLOPT_POST, 0L);
        curl_easy_setopt(conf->session, CURLOPT_POSTFIELDS, NULL);

        url = apr_psprintf(url_pool, "%s?username=%s&password=%s", conf->url,
                           url_pescape(url_pool, user), url_pescape(url_pool, sent_pw));
    }

    curl_easy_setopt(conf->session, CURLOPT_URL, url);

    /* get response code - 200 OK, 404 NOT OK */
    if (curl_easy_perform(conf->session) == CURLE_OK)
        res = AUTH_GRANTED;
    else /* this might be something else than a 404 */
        res = AUTH_DENIED;

    apr_pool_destroy(url_pool);
    curl_easy_reset(conf->session);

    /*ap_log_rerror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, r,
                  "REST auth URL request: %s", url);*/
    return res;
}

/* module stuff */

static const authn_provider authn_url_provider =
{
    &check_url,
    NULL
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "url",
                              AUTHN_PROVIDER_VERSION,
                              &authn_url_provider, AP_AUTH_INTERNAL_PER_CONF);

}

AP_DECLARE_MODULE(authn_url) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_url_dir_config,  /* create config structure per directory */
    NULL,                         /* dir merger ensure strictness */
    NULL,                         /* server config */
    NULL,                         /* merge server config */
    authn_url_cmds,               /* command apr_table_t */
    register_hooks                /* register hooks */
};
