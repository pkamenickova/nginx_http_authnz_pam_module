Nginx PAM module for authn and authz
=================================
ngx_http_authnz_pam_module adds PAM authentication and authorization to nginx web server. It extends stogh's PAM module which uses PAM only as authentication/authorization provider for Basic authentication and adds an authorization support for different authentication modules (e.g. [Kerberos](https://github.com/stnoonan/spnego-http-auth-nginx-module)).

This module is still WIP.


Installation
-------------
1. Install [nginx](http://wiki.nginx.org/Install).
1. Clone this module.
1. Add the authnz modules through --add-module option. PAM module should be added last. For example:

	./configure --add-module=spnego-http-auth-nginx-module --add-module=nginx_http_authnz_pam_module


Configuration
-------------
You can set the PAM module through these directives:
* `authnz_pam on|off`: Default value is `off`
* `authnz_pam_service`: PAM service name. This directive is required and must contain non-empty string.
* `authnz_pam_basic_fallback on|off`: Use the Basic HTTP authentication in case of failure of previous authentication module failure. Default value is `off`. For now it's not recommended to use this directive without previous authentication module.
* `authnz_pam_name`: Realm used for Basic HTTP authentication. Default value is `PAM realm`.
* `authnz_pam_expired_redirect_url`: URL used for redirection in case of expired authentication token.

Debugging
-------------
Debugging information can be obtained through the `--with-debug` option used during nginx compilation. The `error_log` directive must be set to `debug` level.
