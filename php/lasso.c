/*  
 *
 * PHP lasso -- PHP bindings for Lasso library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Christophe Nowicki <cnowicki@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_lasso.h"

#ifdef HAVE_CONFIG_H
#include "lasso_config.h"
#endif


#include "lasso.h"

/* True global resources - no need for thread safety here */
int le_lasso;
int le_lassonode;
int le_lassoserver;
int le_lassologin;
int le_lassologout;
int le_lassouser;
int le_lassofederation;
int le_lassosession;
int le_lassoidentity;
int le_lassoprofile;
int le_lassolibauthnrequest;

ZEND_DECLARE_MODULE_GLOBALS(lasso)

/* {{{ lasso_functions[]
 *
 * Every user visible function must have an entry in lasso_functions[].
 */
function_entry lasso_functions[] = {
	PHP_FE(lasso_init,	NULL)
	PHP_FE(lasso_version,	NULL)
	PHP_FE(lasso_shutdown,	NULL)
	
	/* lasso_server.c */
	PHP_FE(lasso_server_new,	NULL)
	PHP_FE(lasso_server_dump,	NULL)
	PHP_FE(lasso_server_add_provider,	NULL)
	PHP_FE(lasso_server_destroy,	NULL)
	PHP_FE(lasso_server_new_from_dump,	NULL)
	
	/* lasso_login.c */
	PHP_FE(lasso_login_new,	NULL)
	PHP_FE(lasso_login_new_from_dump,	NULL)
	PHP_FE(lasso_login_init_authn_request,	NULL)
	PHP_FE(lasso_login_destroy,	NULL)
	PHP_FE(lasso_login_build_request_msg,	NULL)
	PHP_FE(lasso_login_build_authn_request_msg,	NULL)
	PHP_FE(lasso_login_init_request,	NULL)
	PHP_FE(lasso_login_process_response_msg,	NULL)
	PHP_FE(lasso_login_accept_sso,	NULL)

	/* lasso_user.c */
	PHP_FE(lasso_identity_new,	NULL)
	PHP_FE(lasso_identity_dump,	NULL)
	PHP_FE(lasso_identity_destroy,	NULL)

	/* lasso_profile.c */
	PHP_FE(lasso_profile_new,	NULL)
	PHP_FE(lasso_profile_dump,	NULL)
	PHP_FE(lasso_profile_set_remote_providerid,	NULL)
	PHP_FE(lasso_profile_set_response_status,	NULL)
	PHP_FE(lasso_profile_user_from_dump,	NULL)
	PHP_FE(lasso_profile_get_request_type_from_soap_msg,	NULL)
	PHP_FE(lasso_cast_to_profile,	NULL)
	PHP_FE(lasso_profile_get_request,	NULL)
	PHP_FE(lasso_profile_get_msg_url,	NULL)
	PHP_FE(lasso_profile_get_msg_body,	NULL)
	PHP_FE(lasso_profile_get_msg_relaystate,	NULL)
	PHP_FE(lasso_profile_get_identity,	NULL)
	PHP_FE(lasso_profile_is_identity_dirty,	NULL)
	PHP_FE(lasso_profile_get_session,	NULL)
	PHP_FE(lasso_profile_is_session_dirty,	NULL)
	PHP_FE(lasso_profile_get_nameidentifier,	NULL)
	PHP_FE(lasso_profile_set_identity_from_dump,	NULL)
	
	/* lasso_lib_authn_request.c */
	PHP_FE(lasso_cast_to_lib_authn_request,	NULL)
	PHP_FE(lasso_lib_authn_request_set_consent,	NULL)
	PHP_FE(lasso_lib_authn_request_set_ispassive,	NULL)
	PHP_FE(lasso_lib_authn_request_set_forceauthn,	NULL)
	PHP_FE(lasso_lib_authn_request_set_nameidpolicy,	NULL)
	PHP_FE(lasso_lib_authn_request_set_relaystate,	NULL)
	PHP_FE(lasso_lib_authn_request_set_protocolprofile,	NULL)
	PHP_FE(lasso_lib_authn_response_set_consent,	NULL)

	/* lasso_identity */
	PHP_FE(lasso_federation_new,	NULL)

	/* lasso_session.c */
	PHP_FE(lasso_session_dump,	NULL)

	/* lasso_logout.c */
	PHP_FE(lasso_logout_new,	NULL)
	PHP_FE(lasso_logout_init_request,	NULL)
	PHP_FE(lasso_logout_build_request_msg,	NULL)

	{NULL, NULL, NULL}	
};
/* }}} */

/* {{{ lasso_module_entry
 */
zend_module_entry lasso_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"lasso",
	lasso_functions,
	PHP_MINIT(lasso),
	PHP_MSHUTDOWN(lasso),
	PHP_RINIT(lasso),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(lasso),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(lasso),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

ZEND_GET_MODULE(lasso)

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("lasso.global_value",      "42", PHP_INI_ALL, OnUpdateInt, global_value, zend_lasso_globals, lasso_globals)
    STD_PHP_INI_ENTRY("lasso.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_lasso_globals, lasso_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ */
void lassonode_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoNode *my_rsrc = (LassoNode *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ */
void lassoserver_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoServer *my_rsrc = (LassoServer *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ */
void lassologin_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoLogin *my_rsrc = (LassoLogin *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{  */
void lassoidentity_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoIdentity *my_rsrc = (LassoIdentity *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{  */
void lassosession_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoSession *my_rsrc = (LassoSession *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ */
void lassoprofile_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoProfile *my_rsrc = (LassoProfile *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ */
void lassofederation_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoFederation *my_rsrc = (LassoFederation *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ */
void lassolibauthnrequest_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoLibAuthnRequest *my_rsrc = (LassoLibAuthnRequest *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ */
void lassologout_destruction_handler(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
	LassoLogout *my_rsrc = (LassoLogout *) rsrc->ptr;
    // do_whatever_needs_to_be_done_with_the_resource(my_rsrc);
}
/* }}} */

/* {{{ php_lasso_init_globals
 */
static void php_lasso_init_globals(zend_lasso_globals *lasso_globals)
{
	lasso_globals->global_value = 0;
	lasso_globals->global_string = NULL;
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(lasso)
{
	ZEND_INIT_MODULE_GLOBALS(lasso, php_lasso_init_globals, NULL);
/*	REGISTER_INI_ENTRIES(); */

	/* Resources */
	le_lassonode = zend_register_list_destructors_ex(lassonode_destruction_handler, NULL, le_lassonode_name, module_number);
	le_lassoserver = zend_register_list_destructors_ex(lassoserver_destruction_handler, NULL, le_lassoserver_name, module_number);
	le_lassologin = zend_register_list_destructors_ex(lassologin_destruction_handler, NULL, le_lassologin_name, module_number);
	le_lassologout = zend_register_list_destructors_ex(lassologout_destruction_handler, NULL, le_lassologout_name, module_number);
	le_lassoidentity = zend_register_list_destructors_ex(lassoidentity_destruction_handler, NULL, le_lassoidentity_name, module_number);
	le_lassosession = zend_register_list_destructors_ex(lassosession_destruction_handler, NULL, le_lassosession_name, module_number);
	le_lassofederation = zend_register_list_destructors_ex(lassofederation_destruction_handler, NULL, le_lassofederation_name, module_number);
	le_lassoprofile = zend_register_list_destructors_ex(lassoprofile_destruction_handler, NULL, le_lassoprofile_name, module_number);
	le_lassolibauthnrequest = zend_register_list_destructors_ex(lassolibauthnrequest_destruction_handler, NULL, le_lassolibauthnrequest_name, module_number);
	

	/* Constants */
	REGISTER_LONG_CONSTANT("lassoSignatureMethodRsaSha1", 1, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("lassoLibConsentObtained", (char *) lassoLibConsentObtained, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("lassoLibNameIDPolicyTypeFederated", (char *)lassoLibNameIDPolicyTypeFederated, CONST_CS | CONST_PERSISTENT);
	REGISTER_STRING_CONSTANT("lassoLibProtocolProfileBrwsArt", (char *) lassoLibProtocolProfileBrwsArt, CONST_CS | CONST_PERSISTENT);

	/* lassoHttpMethod */
	REGISTER_LONG_CONSTANT("lassoHttpMethodGet", 1, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("lassoHttpMethodPost", 2, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("lassoHttpMethodRedirect", 3, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("lassoHttpMethodSoap", 4, CONST_CS | CONST_PERSISTENT);

	/* lassoProviderType */
	REGISTER_LONG_CONSTANT("lassoProviderTypeNone", 1, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("lassoProviderTypeSp", 2, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("lassoProviderTypeIdp", 3, CONST_CS | CONST_PERSISTENT);
		
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(lasso)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(lasso)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(lasso)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(lasso)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "L.A.S.O.O support", "enabled");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */



/* Remove the following function when you have succesfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* {{{ proto long lasso_init()
   Initialise le bourdel */
PHP_FUNCTION(lasso_init)
{
	
	if (ZEND_NUM_ARGS() != 0) 
		WRONG_PARAM_COUNT

	RETURN_LONG(lasso_init());

}
/* }}} */

/* {{{ proto long lasso_shutdown() */
PHP_FUNCTION(lasso_shutdown)
{
	
	if (ZEND_NUM_ARGS() != 0) 
		WRONG_PARAM_COUNT

	RETURN_LONG(lasso_shutdown());

}
/* }}} */

/* {{{ proto string lasso_version() */
PHP_FUNCTION(lasso_version)
{
	char lasso_version[6];

	snprintf(lasso_version, 6, "%d.%d.%d", LASSO_VERSION_MAJOR, 
			LASSO_VERSION_MINOR, LASSO_VERSION_SUBMINOR);

	RETURN_STRING(lasso_version, 1)
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
