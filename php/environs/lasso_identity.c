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

/* {{{ proto resource lasso_identity_new() */
PHP_FUNCTION(lasso_identity_new) {
	LassoIdentity *identity;
	
	zend_printf("DEBUG: lasso_identity_new\n");

	identity = lasso_identity_new();

	ZEND_REGISTER_RESOURCE(return_value, identity, le_lassoidentity);
}
/* }}} */

/* {{{ proto lasso_identity_destroy(resource identity) */
PHP_FUNCTION(lasso_identity_destroy) {

	LassoIdentity *identity;
	zval *param;

	zend_printf("DEBUG: lasso_identity_destroy\n");

	int num_args;

	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(identity, LassoIdentity *, &param, -1, le_lassoidentity_name, le_lassoidentity);
	
	zend_printf("DEBUG: identity at 0x%p\n", identity);

	lasso_identity_destroy(identity);

	zend_list_delete(Z_RESVAL_PP(&param));
}
/* }}} */

/* {{{ proto lasso_identity_dump(resource identity) */
PHP_FUNCTION(lasso_identity_dump) {
	LassoIdentity *identity;
	zval *param;
	char *identity_dump;
	
	int num_args;

	zend_printf("DEBUG: lasso_identity_dump\n");
	
	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(identity, LassoIdentity *, &param, -1, le_lassoidentity_name, le_lassoidentity);
	
	zend_printf("DEBUG: identity at 0x%p\n", identity);

	identity_dump = lasso_identity_dump(identity);

	RETURN_STRING(identity_dump, 1);

}
/* }}} */
