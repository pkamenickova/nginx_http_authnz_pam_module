Nginx PAM module for authn and authz
=================================
ngx_http_authnz_pam_module adds PAM authentication and authorization to nginx web server and provides authorization support for authentication modules (e.g. [Kerberos](https://github.com/stnoonan/spnego-http-auth-nginx-module)).
It extends [stogh's PAM module](https://github.com/stogh/ngx_http_auth_pam_module) which uses PAM only as authentication/authorization provider for Basic HTTP authentication.

This module is still WIP.


Installation
-------------
1. Install [nginx](http://wiki.nginx.org/Install).
1. Clone this module.
1. Install pam-devel package.
1. Add the authnz modules through --add-module option. PAM module should be added last. For example:

	./configure --add-module=spnego-http-auth-nginx-module --add-module=nginx_http_authnz_pam_module


Configuration
-------------
You can set the PAM module through these directives:
* `authnz_pam on|off`: Default value is `off`
* `authnz_pam_service`: PAM service name. This directive is required and must contain non-empty string.
* `authnz_pam_basic_fallback on|off`: Default value is `off`. Use the Basic HTTP authentication in case of failure of previous authentication module. 
Basic authentication fallback can be used on its own (without previous authentication module) but it's not recommended for now.
* `authnz_pam_name`: Realm used for Basic HTTP authentication. Default value is `PAM realm`.
* `authnz_pam_expired_redirect_url`: URL used for redirection in case of expired authentication token.


Example configuration
-------------
To use PAM on location /test add following lines into `conf/nginx.conf`:

    location /test {
        satisfy all;

        #configuration directives of authentication module (e.g. [Kerberos](https://github.com/stnoonan/spnego-http-auth-nginx-module))
	auth_gss on;
        auth_gss_keytab /etc/http.keytab;
        auth_gss_realm EXAMPLE.TEST;
        auth_gss_service_name HTTP/test.example.test;

	#configuration directives of PAM module - authorization
	authnz_pam on;
        authnz_pam_service "random-svc";
	authnz_pam_expired_redirect_url "https://auth.example.test/reset_password";
    }

If you want to use PAM module as an authentication/authorization provider for Basic authentication try this:

    location /test2 {
        satisfy any;

        authnz_pam on;
        authnz_pam_service random-svc;

        authnz_pam_basic_fallback on;
        authnz_pam_name "Basic realm=PAM";

    }

(The "satisfy any" directive does not make much sense for now (because if previous authn module succeeds then PAM module is not called), but I'm working on solution.)



Now you have to create PAM service configuration file (in this case /etc/pam.d/random-svc) and specify which PAM modules will be used. For example to authenticate/authorize throught SSSD use following lines:

    auth        required        pam_sss.so
    account     required        pam_sss.so

If /etc/pam.d/<service name> file doesn't exist, the default /etc/pam.conf is used.

Debugging
-------------
Debugging information can be obtained through the `--with-debug` option used during nginx compilation. The `error_log` directive must be set to `debug` level.
