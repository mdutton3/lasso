/*
  +----------------------------------------------------------------------+
  | PHP Version 4                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2003 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.02 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available at through the world-wide-web at                           |
  | http://www.php.net/license/2_02.txt.                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+

  $Id$ 
*/

#ifndef PHP_LASSO_H
#define PHP_LASSO_H

extern zend_module_entry lasso_module_entry;
#define phpext_lasso_ptr &lasso_module_entry

#ifdef PHP_WIN32
#define PHP_LASSO_API __declspec(dllexport)
#else
#define PHP_LASSO_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/* Avoid warning about multiple definitions */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

/* Resource */
#define le_lassonode_name  "LASSO Node Resource"
#define le_lassoserver_name  "LASSO Server Resource"
#define le_lassologin_name  "LASSO Login Resource"
#define le_lassologout_name  "LASSO Logout Resource"
#define le_lassoidentity_name  "LASSO Identity Resource"
#define le_lassosession_name  "LASSO Session Resource"
#define le_lassofederation_name  "LASSO Federation Resource"
#define le_lassoprofile_name  "LASSO Profile Resource"
#define le_lassolibauthnrequest_name  "LASSO Lib Authn Request Resource"

PHP_MINIT_FUNCTION(lasso);
PHP_MSHUTDOWN_FUNCTION(lasso);
PHP_RINIT_FUNCTION(lasso);
PHP_RSHUTDOWN_FUNCTION(lasso);
PHP_MINFO_FUNCTION(lasso);

PHP_FUNCTION(lasso_init);	
PHP_FUNCTION(lasso_version);	
PHP_FUNCTION(lasso_shutdown);	

/* lasso_server.c */
PHP_FUNCTION(lasso_server_new);	
PHP_FUNCTION(lasso_server_dump);	
PHP_FUNCTION(lasso_server_add_provider);	
PHP_FUNCTION(lasso_server_destroy);	
PHP_FUNCTION(lasso_server_new_from_dump);	

/* lasso_login.c */
PHP_FUNCTION(lasso_login_new);	
PHP_FUNCTION(lasso_login_new_from_dump);
PHP_FUNCTION(lasso_login_init_authn_request);
PHP_FUNCTION(lasso_login_destroy);
PHP_FUNCTION(lasso_login_build_authn_request_msg);
PHP_FUNCTION(lasso_login_init_request);
PHP_FUNCTION(lasso_login_build_request_msg);
PHP_FUNCTION(lasso_login_process_response_msg);
PHP_FUNCTION(lasso_login_accept_sso);

/* lasso_identity.c */
PHP_FUNCTION(lasso_identity_new);	
PHP_FUNCTION(lasso_identity_dump);	
PHP_FUNCTION(lasso_identity_destroy);	

/* lasso_federation.c */
PHP_FUNCTION(lasso_federation_new);	

/* lasso_session.c */
PHP_FUNCTION(lasso_session_dump);	

/* lasso_profile_.c */
PHP_FUNCTION(lasso_profile_new);	
PHP_FUNCTION(lasso_profile_dump);	
PHP_FUNCTION(lasso_profile_set_remote_providerid);	
PHP_FUNCTION(lasso_profile_set_response_status);	
PHP_FUNCTION(lasso_profile_user_from_dump);	
PHP_FUNCTION(lasso_profile_get_request_type_from_soap_msg);	
PHP_FUNCTION(lasso_cast_to_profile);	
PHP_FUNCTION(lasso_profile_get_request);	
PHP_FUNCTION(lasso_profile_get_msg_url);	
PHP_FUNCTION(lasso_profile_get_msg_body);	
PHP_FUNCTION(lasso_profile_get_msg_relaystate);	
PHP_FUNCTION(lasso_profile_get_identity);	
PHP_FUNCTION(lasso_profile_is_identity_dirty);	
PHP_FUNCTION(lasso_profile_get_session);	
PHP_FUNCTION(lasso_profile_is_session_dirty);	
PHP_FUNCTION(lasso_profile_get_nameidentifier);	
PHP_FUNCTION(lasso_profile_set_identity_from_dump);

/* lasso_lib_authn_request.c */
PHP_FUNCTION(lasso_cast_to_lib_authn_request);
PHP_FUNCTION(lasso_lib_authn_request_set_consent);
PHP_FUNCTION(lasso_lib_authn_request_set_ispassive);
PHP_FUNCTION(lasso_lib_authn_request_set_forceauthn);
PHP_FUNCTION(lasso_lib_authn_request_set_nameidpolicy);
PHP_FUNCTION(lasso_lib_authn_request_set_relaystate);
PHP_FUNCTION(lasso_lib_authn_request_set_protocolprofile);
PHP_FUNCTION(lasso_lib_authn_response_set_consent);

/* lasso_logout.c */
PHP_FUNCTION(lasso_logout_new);
PHP_FUNCTION(lasso_logout_init_request);
PHP_FUNCTION(lasso_logout_build_request_msg);

/* GLOBALS */
ZEND_BEGIN_MODULE_GLOBALS(lasso)
	long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(lasso)

/* global resoucres */
extern int le_lasso;
extern int le_lassonode;
extern int le_lassoserver;
extern int le_lassologin;
extern int le_lassologout;
extern int le_lassoidentity;
extern int le_lassosession;
extern int le_lassofederation;
extern int le_lassoprofile;
extern int le_lassolibauthnrequest;

/* In every utility function you add that needs to use variables 
   in php_lasso_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as LASSO_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define LASSO_G(v) TSRMG(lasso_globals_id, zend_lasso_globals *, v)
#else
#define LASSO_G(v) (lasso_globals.v)
#endif

#endif	/* PHP_LASSO_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 */
