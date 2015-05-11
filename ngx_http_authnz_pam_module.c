#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <security/pam_appl.h>

static ngx_int_t ngx_http_authnz_pam_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_authnz_pam_init(ngx_conf_t *cf);
static void *ngx_http_authnz_pam_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_authnz_pam_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

#define pam_authnz_debug0(msg) ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg)
#define pam_authnz_debug1(msg, one) ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, msg, one)

#define _PAM_STEP_AUTH 1
#define _PAM_STEP_ACCOUNT 2

#define _DEFAULT_PAM_REALM "PAM realm"
#define _DEFAULT_PAM_SERVICE "nginx"

typedef struct {
    ngx_flag_t  active;
    ngx_str_t   name;          
    ngx_str_t   pam_service_name;
    ngx_flag_t  basic_auth_fallback;
    ngx_str_t   expired_redirect_url;
} ngx_http_authnz_pam_loc_conf_t;

static ngx_command_t ngx_http_authnz_pam_commands[] = {
    { ngx_string("authnz_pam"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_authnz_pam_loc_conf_t, active),
      NULL
    },

    { ngx_string("authnz_pam_name"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_authnz_pam_loc_conf_t, name),
      NULL
    },

    { ngx_string("authnz_pam_service"),  
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_authnz_pam_loc_conf_t, pam_service_name),
      NULL
    },

    { ngx_string("authnz_pam_basic_fallback"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_authnz_pam_loc_conf_t, basic_auth_fallback),
      NULL
    },

    { ngx_string("authnz_pam_expired_redirect_url"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_authnz_pam_loc_conf_t, expired_redirect_url),
      NULL
    },

    ngx_null_command
};

static ngx_int_t ngx_http_authnz_pam_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_authnz_pam_handler;

    return NGX_OK;
}


static void * ngx_http_authnz_pam_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_authnz_pam_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_authnz_pam_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->active = NGX_CONF_UNSET;
    conf->basic_auth_fallback = NGX_CONF_UNSET;

    return conf;
}

static char * ngx_http_authnz_pam_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_authnz_pam_loc_conf_t *prev = parent;
    ngx_http_authnz_pam_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->basic_auth_fallback, prev->basic_auth_fallback, 0);
    ngx_conf_merge_off_value(conf->active, prev->active, 0);
    ngx_conf_merge_str_value(conf->name, prev->name, _DEFAULT_PAM_REALM);
    ngx_conf_merge_str_value(conf->pam_service_name, prev->pam_service_name, _DEFAULT_PAM_SERVICE);
    ngx_conf_merge_str_value(conf->expired_redirect_url, prev->expired_redirect_url, "");

    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_authnz_pam_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_authnz_pam_init,      /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_authnz_pam_create_loc_conf,  /* create location configuration */
    ngx_http_authnz_pam_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_authnz_pam_module = {
    NGX_MODULE_V1,
    &ngx_http_authnz_pam_module_ctx,
    ngx_http_authnz_pam_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};   


/* 
 * If authentication credentials are missing, return appropriate response. 
 * Correct status code: 401 Unauthorized
 * WWW-Authenticate header field must be included
 */
static ngx_int_t ngx_http_authnz_pam_return_www_auth(ngx_http_request_t *r, ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

/*
 * Supply auth data to PAM
 *
 */
static int ngx_auth_pam_conv(int num_msg, const struct pam_message ** msg, struct pam_response ** resp, void *appdata_ptr)
{
    struct pam_response * response = NULL;

    if (!msg || !resp || !appdata_ptr)
        return PAM_CONV_ERR;

    if (!(response = malloc(num_msg * sizeof(struct pam_response))))
        return PAM_CONV_ERR;

    int i;
    for (i = 0; i < num_msg; i++) 
    {
        response[i].resp = 0;
        response[i].resp_retcode = 0;
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) 
            response[i].resp = strdup(appdata_ptr);
        else 
        {
            free(response);
            return PAM_CONV_ERR;
        }
    }
    * resp = response;
    return PAM_SUCCESS;
}


static ngx_int_t ngx_http_pam_authenticate(ngx_http_request_t *r, ngx_int_t steps, ngx_http_authnz_pam_loc_conf_t *loc_conf, const char * user, const char * password)
{
    int ret;
    pam_handle_t * pamh = NULL;
    struct pam_conv pam_conversation = { &ngx_auth_pam_conv, (void *) password };
 
    ret = pam_start((const char *) loc_conf->pam_service_name.data, user, &pam_conversation, &pamh);

    if (ret == PAM_SUCCESS) {
       if (steps & _PAM_STEP_AUTH) {
           ret = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
       }

       if ((ret == PAM_SUCCESS) && (steps & _PAM_STEP_ACCOUNT)) {
           ret = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK);
       }

       if (ret == PAM_NEW_AUTHTOK_REQD) {
           if (loc_conf->expired_redirect_url.len != 0) {
               pam_authnz_debug1("pam_authnz: Redirect to: %s", loc_conf->expired_redirect_url.data);

               r->headers_out.location = ngx_list_push(&r->headers_out.headers);
               if (r->headers_out.location == NULL) {
                   return NGX_HTTP_INTERNAL_SERVER_ERROR;
               }

               r->headers_out.location->hash = 1;
               r->headers_out.location->key.len = sizeof("Location") - 1;
               r->headers_out.location->key.data = (u_char *) "Location";
               r->headers_out.location->value.len = loc_conf->expired_redirect_url.len;              
               r->headers_out.location->value.data = loc_conf->expired_redirect_url.data;
               return NGX_HTTP_TEMPORARY_REDIRECT;
           }
       }
     
       pam_end(pamh, ret); 
       if (ret == PAM_SUCCESS)
           return NGX_OK;

       return NGX_HTTP_FORBIDDEN;
    }
    else {
       pam_authnz_debug1("pam_authnz: PAM service could not start: ",pam_strerror(pamh, ret));
       pam_end(pamh, ret);
       return NGX_ERROR;
    } 
}

/*
 * Module handler
 *
 */
static ngx_int_t ngx_http_authnz_pam_handler(ngx_http_request_t *r)
{
    ngx_int_t steps = 0;
    ngx_int_t rc;
    ngx_http_authnz_pam_loc_conf_t  *loc_conf;

    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_authnz_pam_module);

    if (loc_conf->active == 0) {
        return NGX_DECLINED;
    }

    if (loc_conf->pam_service_name.len == 0) {
        pam_authnz_debug0("pam_authnz: Empty PAM service name");
        return NGX_ERROR;
    }

    pam_authnz_debug1("pam_authnz: PAM service name is set to: %s", loc_conf->pam_service_name.data);

    if (r->headers_in.user.data == NULL) {
    	if (loc_conf->basic_auth_fallback == 1) {
			//Basic authentication fallback
			//Called only if satisfy any is set and Kerberos failed,
			//which is bad configuration, but still have to be handled.
			//or if there is no Kerberos configured at all
			//that means I have to authenticate before authorization
			pam_authnz_debug0("pam_authnz: Basic auth fallback");
			rc = ngx_http_auth_basic_user(r);

			if (rc == NGX_DECLINED) {
				return ngx_http_authnz_pam_return_www_auth(r, &loc_conf->name);
			}
			if (rc == NGX_ERROR) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			steps = _PAM_STEP_AUTH;
		}
        else {
   	    	return NGX_HTTP_UNAUTHORIZED;
        }
    }
  
    u_char *name_buf, *pass_buf, *p;
    size_t name_len, pass_len;

    for (name_len = 0; name_len < r->headers_in.user.len; name_len++) {
        if (r->headers_in.user.data[name_len] == ':') {
            break;
        }
    }

    for (pass_len = 0; ; pass_len++) {
        if (r->headers_in.user.data[name_len + pass_len] == '\0') {
            break;
        }
    }

    name_buf = ngx_palloc(r->pool, name_len+1);
    if (name_buf == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(name_buf, r->headers_in.user.data , name_len);
    *p = '\0';
    pass_buf = ngx_palloc(r->pool, pass_len+1 );
    if (pass_buf == NULL) {
        return NGX_ERROR;
    }
    
    p = ngx_cpymem(pass_buf, &(r->headers_in.user.data[name_len+1]), pass_len);
    *p = '\0';

    steps = steps + _PAM_STEP_ACCOUNT;
    rc = ngx_http_pam_authenticate(r, steps, loc_conf, (const char *) name_buf,  (const char *) pass_buf);
    return rc;
};
