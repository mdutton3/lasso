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

/* {{{ proto resource lasso_logout_new(resource server, long provider_type) */
PHP_FUNCTION(lasso_logout_new) {

  	LassoLogout *logout;
	LassoServer  *server;
	zval *param;
	long provider_type;

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 2) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zl", 
		  &param, &provider_type) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &param, -1, le_lassoserver_name, le_lassoserver);
	
  	logout = lasso_logout_new(server, provider_type);

	ZEND_REGISTER_RESOURCE(return_value, logout, le_lassologout);
}
/* }}} */

/* {{{ proto resource lasso_logout_init_request(resource logout, string remote_providerid) */
PHP_FUNCTION(lasso_logout_init_request) {

  	LassoLogout *logout;
	char *remote_providerid = 0;
	int remote_providerid_len = 0;
	zval *param;
	long provider_type;

	int num_args;

	num_args = ZEND_NUM_ARGS();
	if (num_args != 1 && num_args != 2) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z|s", 
		  &param, &remote_providerid, &remote_providerid_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(logout, LassoLogout *, &param, -1, le_lassologout_name, le_lassologout);
	
  	lasso_logout_init_request(logout, remote_providerid);
}
/* }}} */

/* {{{ proto resource lasso_logout_build_request_msg(resource logout) */
PHP_FUNCTION(lasso_logout_build_request_msg) {

  	LassoLogout *logout;
	zval *param;
	long provider_type;

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(logout, LassoLogout *, &param, -1, le_lassologout_name, le_lassologout);
	
  	lasso_logout_build_request_msg(logout);
}
/* }}} */
