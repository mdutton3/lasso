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

/* {{{ proto string lasso_session_dump(resource server) */
PHP_FUNCTION(lasso_session_dump) {

	LassoSession  *session;
	zval *param;
	char *session_dump;
	
	int num_args;
	
	if ((num_args = ZEND_NUM_ARGS()) != 1) 
		WRONG_PARAM_COUNT

	if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(session, LassoSession *, &param, -1, le_lassosession_name, le_lassosession);
	
	session_dump = lasso_session_dump(session);

	RETURN_STRING(session_dump, 1);
}
/* }}} */
