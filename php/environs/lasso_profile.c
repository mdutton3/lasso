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
#include "../php_lasso.h"

#ifdef HAVE_CONFIG_H
#include "lasso_config.h"
#endif


#include "lasso.h"

/* {{{ proto lasso_profile_new(resource server, resource identity, resource session) */
PHP_FUNCTION(lasso_profile_new) 
{
  	LassoServer  			*server;  
	LassoIdentity  	 		*identity;  
	LassoSession  	 		*session;  
	LassoProfile     		*ctx;  

	zval *parm_server, *parm_identity, *parm_session;

  	

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 3) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zzz", 
		  &parm_server, &parm_identity, &parm_session) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &parm_server, -1, le_lassoserver_name, le_lassoserver);
	

	ZEND_FETCH_RESOURCE(identity, LassoIdentity *, &parm_identity, -1, le_lassoidentity_name, le_lassoidentity);
	
	ZEND_FETCH_RESOURCE(session, LassoSession *, &parm_session, -1, le_lassosession_name, le_lassosession);
	
	ctx = lasso_profile_new(server, identity, session);

	ZEND_REGISTER_RESOURCE(return_value, ctx, le_lassoprofile);

}
/* }}} */

/* TODO {{{ proto lasso_profile_dump() */
PHP_FUNCTION(lasso_profile_dump) 
{
  
}
/* }}} */

/* TODO {{{ proto lasso_profile_set_remote_providerid() */
PHP_FUNCTION(lasso_profile_set_remote_providerid) 
{
  
}
/* }}} */

/* TODO {{{ proto lasso_profile_set_response_status() */
PHP_FUNCTION(lasso_profile_set_response_status) 
{
  
}
/* }}} */

/* TODO {{{ proto lasso_profile_user_from_dump() */
PHP_FUNCTION(lasso_profile_user_from_dump) 
{
  
}
/* }}} */

/* TODO {{{ proto lasso_profile_get_request_type_from_soap_msg() */
PHP_FUNCTION(lasso_profile_get_request_type_from_soap_msg) 
{
  
}
/* }}} */

/* {{{ proto resource lasso_cast_to_profile(resource login|logout) */
PHP_FUNCTION(lasso_cast_to_profile) 
{
  	LassoProfile	*ctx;  
  	LassoLogin   	*login;  
  	LassoLogout   	*logout;  

	zval *parm;
	char *typename;
	int num_args;
	int ret;

	ctx = 0;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	typename = zend_rsrc_list_get_rsrc_type(Z_LVAL_P(parm) TSRMLS_CC);

	if (strcmp(typename, le_lassologin_name) == 0)
	{
	  ZEND_FETCH_RESOURCE(login, LassoLogin *, &parm, -1, le_lassologin_name, le_lassologin);
	  ctx = LASSO_PROFILE(login);
	} 
	else if (strcmp(typename, le_lassologout_name) == 0) 
	{
	  ZEND_FETCH_RESOURCE(logout, LassoLogout *, &parm, -1, le_lassologout_name, le_lassologout);
	  ctx = LASSO_PROFILE(logout);
	}
	else
	{
	  zend_error(E_ERROR, "Can not cast %s to LassoProfile", typename);
	}

	if (ctx)
	  ZEND_REGISTER_RESOURCE(return_value, ctx, le_lassoprofile);
}
/* }}} */

/* {{{ proto resource lasso_profile_get_request(resource ctx) */
PHP_FUNCTION(lasso_profile_get_request) {
	LassoProfile	*ctx;  
  	LassoNode   		*node;  

  	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);
	

	node = ctx->request;

	ZEND_REGISTER_RESOURCE(return_value, node, le_lassonode);
}

/* {{{ proto string lasso_profile_get_msg_url(resource ctx) */
PHP_FUNCTION(lasso_profile_get_msg_url) {
	LassoProfile	*ctx;  
  	LassoNode   		*node;  

  	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);
	
	if (ctx->msg_url)
	  RETURN_STRING(ctx->msg_url, 1);
}
/* }}} */

/* {{{ proto string lasso_profile_get_msg_body(resource ctx) */
PHP_FUNCTION(lasso_profile_get_msg_body) {
	LassoProfile	*ctx;  
  	LassoNode   		*node;  

  	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);
	
	if (ctx->msg_body)
	  RETURN_STRING(ctx->msg_body, 1);
}
/* }}} */

/* {{{ proto string lasso_profile_get_msg_relaystate(resource ctx) */
PHP_FUNCTION(lasso_profile_get_msg_relaystate) {
	LassoProfile	*ctx;  
  	LassoNode   		*node;  

  	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);
	
	if (ctx->msg_relayState)
	  RETURN_STRING(ctx->msg_relayState, 1);
}
/* }}} */


/* {{{ proto resource lasso_profile_get_identity(resource ctx) */
PHP_FUNCTION(lasso_profile_get_identity) {
	LassoProfile	*ctx;  
	LassoIdentity 	*identity;

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);

	identity = lasso_profile_get_identity(ctx);

	// zend_printf("value of %p\n", identity);
	
	ZEND_REGISTER_RESOURCE(return_value, identity, le_lassoidentity);	
}
/* }}} */

/* {{{ proto bool lasso_profile_is_identity_dirty(resource ctx) */
PHP_FUNCTION(lasso_profile_is_identity_dirty) {
	LassoProfile	*ctx;  

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);

	ret = lasso_profile_is_identity_dirty(ctx);

	RETURN_BOOL(ret);
}
/* }}} */

/* {{{ proto lasso_profile_get_session(resource ctx) */
PHP_FUNCTION(lasso_profile_get_session) {
	LassoProfile	*ctx;  
	LassoSession 	*session;

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);

	session = lasso_profile_get_session(ctx);
	
	ZEND_REGISTER_RESOURCE(return_value, session, le_lassosession);	
}
/* }}} */

/* {{{ proto bool lasso_profile_is_session_dirty(resource ctx) */
PHP_FUNCTION(lasso_profile_is_session_dirty) {
	LassoProfile	*ctx;  

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);

	ret = lasso_profile_is_session_dirty(ctx);

	RETURN_BOOL(ret);
}
/* }}} */


/* {{{ proto string lasso_profile_get_nameidentifier(resource ctx) */
PHP_FUNCTION(lasso_profile_get_nameidentifier) {
	LassoProfile	*ctx;  
  	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);
	
	if (ctx->nameIdentifier)
	  RETURN_STRING(ctx->nameIdentifier, 1);
}
/* }}} */

/* {{{ proto lasso_profile_set_identity_from_dump(resource profile, string dump) */
PHP_FUNCTION(lasso_profile_set_identity_from_dump) {

  	LassoProfile   *ctx;  
	char *dump;
	int dump_len;

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 2) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &parm,
		  &dump, &dump_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);

	lasso_profile_set_identity_from_dump(ctx, dump);
}
/* }}} */

/* {{{ proto lasso_profile_set_session_from_dump(resource profile, string dump) */
PHP_FUNCTION(lasso_profile_set_session_from_dump) {

  	LassoProfile   *ctx;  
	char *dump;
	int dump_len;

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 2) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &parm,
		  &dump, &dump_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, LassoProfile *, &parm, -1, le_lassoprofile_name, le_lassoprofile);

	lasso_profile_set_session_from_dump(ctx, dump);
}
/* }}} */
