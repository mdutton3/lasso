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

/* {{{ proto resource lasso_cast_to_lib_authn_request(resource node) */
PHP_FUNCTION(lasso_cast_to_lib_authn_request) 
{
  LassoNode					*node;  
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  int num_args;


  

  if ((num_args = ZEND_NUM_ARGS()) != 1) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "z", &param) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(node, LassoNode *, &param, -1, 
	  le_lassonode_name, le_lassonode);
	
  lib_authn_request = LASSO_LIB_AUTHN_REQUEST(node);

  ZEND_REGISTER_RESOURCE(return_value, lib_authn_request, le_lassolibauthnrequest);
}
/* }}} */

/* {{{ proto lasso_lib_authn_request_set_consent(resource lib_authn_request, string consent) */
PHP_FUNCTION(lasso_lib_authn_request_set_consent)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  char *consent;
  int consent_len;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &param, 
		&consent, &consent_len) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);
	
  lasso_lib_authn_request_set_consent(lib_authn_request, consent);
}
/* }}} */

/* {{{ proto lasso_lib_authn_response_set_consent(resource lib_authn_request, string consent) */
PHP_FUNCTION(lasso_lib_authn_response_set_consent)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  char *consent;
  int consent_len;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &param, 
		&consent, &consent_len) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);
	
  lasso_lib_authn_response_set_consent(lib_authn_request, consent);
}
/* }}} */


/* {{{ proto lasso_lib_authn_request_set_ispassive(resource lib_authn_request, string consent) */
PHP_FUNCTION(lasso_lib_authn_request_set_ispassive)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  zend_bool ispassive = 1;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zb", &param, &ispassive) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);

  lasso_lib_authn_request_set_isPassive(lib_authn_request, ispassive);
}
/* }}} */

/* {{{ proto lasso_lib_authn_request_set_forceauthn(resource lib_authn_request, string consent) */
PHP_FUNCTION(lasso_lib_authn_request_set_forceauthn)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  zend_bool forceauthn = 1;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zb", &param, &forceauthn) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);

  lasso_lib_authn_request_set_forceAuthn(lib_authn_request, forceauthn);
}
/* }}} */

/* {{{ proto lasso_lib_authn_request_set_nameidpolicy(resource lib_authn_request, string consent) */
PHP_FUNCTION(lasso_lib_authn_request_set_nameidpolicy)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  char *nameidpolicy;
  int nameidpolicy_len;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &param, &nameidpolicy, &nameidpolicy_len) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);
	
  lasso_lib_authn_request_set_nameIDPolicy(lib_authn_request, nameidpolicy);
}
/* }}} */

/* {{{ proto lasso_lib_authn_request_set_relaystate(resource lib_authn_request, string relaystate) */
PHP_FUNCTION(lasso_lib_authn_request_set_relaystate)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  char *relaystate;
  int relaystate_len;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &param, &relaystate, &relaystate_len) == FAILURE) {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);

  lasso_lib_authn_request_set_relayState(lib_authn_request, relaystate);
}
/* }}} */


/* {{{ proto lasso_lib_authn_request_set_protocolprofile(resource lib_authn_request, string protocolprofile) */
PHP_FUNCTION(lasso_lib_authn_request_set_protocolprofile)
{
  LassoLibAuthnRequest   	*lib_authn_request;  
  zval *param;
  char *protocolprofile;
  int protocolprofile_len;
  int num_args;

  

  if ((num_args = ZEND_NUM_ARGS()) != 2) 
	WRONG_PARAM_COUNT

  if (zend_parse_parameters(num_args TSRMLS_CC, "zs", &param, &protocolprofile, &protocolprofile_len) == FAILURE)  {
	return;
  }

  ZEND_FETCH_RESOURCE(lib_authn_request, LassoLibAuthnRequest *, &param, -1, 
	  le_lassolibauthnrequest_name, le_lassolibauthnrequest);

  lasso_lib_authn_request_set_protocolProfile(lib_authn_request, protocolprofile);
}
/* }}} */
