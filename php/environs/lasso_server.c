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


/* {{{ proto lasso_server_new(string sp, string rsapub, string rsakey,
 * string rsacert, long signaturemethod) */
PHP_FUNCTION(lasso_server_new) {

	LassoServer  *server;

	char *sp;
	int  sp_len;
	char *rsapub;
	int  rsapub_len;
	char *rsakey;
	int  rsakey_len;
	char *rsacert;
	int  rsacert_len;
	long signaturemethod;
	
	int num_args;
	
	

	if ((num_args = ZEND_NUM_ARGS()) != 5) 
		WRONG_PARAM_COUNT
	
	if (zend_parse_parameters(num_args TSRMLS_CC, "ssssl", 
				&sp, &sp_len, &rsapub, &rsapub_len,
				&rsakey, &rsakey_len, &rsacert, &rsacert_len,
				&signaturemethod) == FAILURE) {
		return;
	}

	server = lasso_server_new(sp, rsapub, rsakey, rsacert, signaturemethod);

	ZEND_REGISTER_RESOURCE(return_value, server, le_lassoserver);
}
/* }}} */

/* {{{ proto lasso_server_add_provider(resource server, string idp, string a, string b) */
PHP_FUNCTION(lasso_server_add_provider) {

	LassoServer  *server;
	zval *param;
	char *idp;
	int idp_len;
	char *a;
	int a_len;
	char *b;
	int b_len;

	

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 4) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "zsss", &param, 
				&idp, &idp_len, &a, &a_len, &b, &b_len) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &param, -1, le_lassoserver_name, le_lassoserver);
	
	lasso_server_add_provider(server, idp, a, b);


}
/* }}} */

/* {{{ proto string lasso_server_new(resource server) */
PHP_FUNCTION(lasso_server_dump) {

	LassoServer  *server;
	zval *param;
	char *server_dump;
	
	int num_args;

	
	
	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &param, -1, le_lassoserver_name, le_lassoserver);
	
	server_dump = lasso_server_dump(server);

	RETURN_STRING(server_dump, 1);
}
/* }}} */

/* {{{ proto lasso_server_destroy(resource server) */
PHP_FUNCTION(lasso_server_destroy) {

	LassoServer  *server;
	zval *param;

	

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(server, LassoServer *, &param, -1, le_lassoserver_name, le_lassoserver);
	
	lasso_server_destroy(server);

	zend_list_delete(Z_RESVAL_PP(&param));
}
/* }}} */

/* {{{ proto resource lasso_server_new_from_dump(string dump) */
PHP_FUNCTION(lasso_server_new_from_dump) {

	LassoServer  *server;
	char *dump;
	int dump_len;
	int num_args;

	
	
	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "s", 
				&dump, &dump_len) == FAILURE) {
		return;
	}

	server = lasso_server_new_from_dump(dump);
	
	ZEND_REGISTER_RESOURCE(return_value, server, le_lassoserver);
}
/* }}} */


