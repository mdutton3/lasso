/*  
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

/* {{{ proto resource lasso_login_new(resource server) */
PHP_FUNCTION(lasso_login_new) {
	
	LassoLogin *login;
	LassoServer  *server;
	zval *param;

	

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &param, -1, le_lassoserver_name, le_lassoserver);
	
  	login = lasso_login_new(server);

	ZEND_REGISTER_RESOURCE(return_value, login, le_lassologin);
}
/* }}} */

/* {{{ proto resource lasso_login_init_authn_request(resource login) */
PHP_FUNCTION(lasso_login_init_authn_request) {
	LassoLogin *login;
	zval *param;
	char *meta;
	int meta_len;

	

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(login, LassoLogin *, &param, -1, 
			le_lassologin_name, le_lassologin);
	
	ret = lasso_login_init_authn_request(login);

	(ret) ? (RETURN_FALSE) : (RETURN_TRUE);
}
/* }}} */



/* {{{ proto lasso_login_destroy(resource login) */
PHP_FUNCTION(lasso_login_destroy) {

	LassoLogin  *login;
	zval *param;

	

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(login, LassoLogin *, &param, -1, le_lassologin_name, le_lassologin);
	
	lasso_login_destroy(login);

	zend_list_delete(Z_RESVAL_PP(&param));
}
/* }}} */

/* {{{ proto resource lasso_login_new_from_dump(resource server, string dump) */
PHP_FUNCTION(lasso_login_new_from_dump) {
	
	LassoServer  *server;  
	LassoLogin   *login;  
	char 		 *dump;
	int 		 dump_len;

	

	zval *parm_server, *parm_user;

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 2) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &parm_server, 
		 &dump, &dump_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &parm_server, -1, le_lassoserver_name, le_lassoserver);
	

	login = lasso_login_new_from_dump(server, dump);

	ZEND_REGISTER_RESOURCE(return_value, login, le_lassologin);
}
/* }}} */


/* {{{ proto lasso_login_build_request_msg(resource login) */
PHP_FUNCTION(lasso_login_build_request_msg) {

	LassoLogin   *login;  

	

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &parm) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(login, LassoLogin *, &parm, -1, le_lassologin_name, le_lassologin);
	
	lasso_login_build_request_msg(login);
}
/* }}} */

/* {{{ proto lasso_login_build_authn_request_msg(resource login, string remote_providerID) */
PHP_FUNCTION(lasso_login_build_authn_request_msg) {

  	LassoLogin   *login;  
	char *remote_providerID;
	int remote_providerID_len;

	zval *parm;

	int num_args;
	int ret;

	if ((num_args = ZEND_NUM_ARGS()) != 2) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &parm,
		  &remote_providerID, &remote_providerID_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(login, LassoLogin *, &parm, -1, le_lassologin_name, le_lassologin);
	
	lasso_login_build_authn_request_msg(login, remote_providerID);
}
/* }}} */
