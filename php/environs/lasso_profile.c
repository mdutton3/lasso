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

/* {{{ proto lasso_profile_dump() */
PHP_FUNCTION(lasso_profile_dump) 
{
  
}
/* }}} */

/* {{{ proto lasso_profile_set_remote_providerid() */
PHP_FUNCTION(lasso_profile_set_remote_providerid) 
{
  
}
/* }}} */

/* {{{ proto lasso_profile_set_response_status() */
PHP_FUNCTION(lasso_profile_set_response_status) 
{
  
}
/* }}} */

/* {{{ proto lasso_profile_user_from_dump() */
PHP_FUNCTION(lasso_profile_user_from_dump) 
{
  
}
/* }}} */

/* {{{ proto lasso_profile_get_request_type_from_soap_msg() */
PHP_FUNCTION(lasso_profile_get_request_type_from_soap_msg) 
{
  
}
/* }}} */

/* {{{ proto resource lasso_cast_to_profile(resource login) */
PHP_FUNCTION(lasso_cast_to_profile) 
{
  	LassoProfile	*ctx;  
  	LassoLogin   		*login;  

  	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(login, LassoLogin *, &parm, -1, le_lassologin_name, le_lassologin);
	
	ctx = LASSO_PROFILE(login);

	/* zend_printf("ctx %p, login %p\n", ctx, login);

	zend_printf("msg_url %s\n",  ctx->msg_url);
	zend_printf("msg_body %s\n",  ctx->msg_body); */

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
