/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/protocols/single_sign_on_and_federation.h>

LassoNode *lasso_build_authnRequest_from_query(gboolean       verifySignature,
					       const xmlChar *query,
					       const xmlChar *rsapub,
					       const xmlChar *rsakey)
{
     LassoNode *req;
     GData     *gd;
     int        result;

     if(verifySignature==TRUE){
	  result = lasso_str_verify(query, rsapub, rsakey);
	  if(result==-1){
	       return(NULL);
	  }
     }

     gd = lasso_query_to_dict(query);
     if(gd!=NULL){
	  req = lasso_build_full_authnRequest(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstance"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIDPolicy"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd,
												       "AssertionConsumerServiceID"),
								      0),
					      NULL, // AuthnContextClassRef
					      NULL, // AuthnContextStatementRef
					      NULL, // AuthnContextComparison
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0),
					      NULL, // ProxyCount
					      NULL, // IDPList
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0));

	  g_datalist_clear(&gd);
	  return(req);
     }

     return(NULL);
}

LassoNode *lasso_build_authnRequest(const xmlChar *providerID,
				    const xmlChar *nameIDPolicy,
				    const xmlChar *forceAuthn,
				    const xmlChar *isPassive,
				    const xmlChar *protocolProfile,
				    const xmlChar *assertionConsumerServiceID,
				    const xmlChar **authnContextClassRefs,
				    const xmlChar **authnContextStatementRefs,
				    const xmlChar *authnContextComparison,
				    const xmlChar *relayState,
				    const xmlChar *proxyCount,
				    const xmlChar **idpList,
				    const xmlChar *consent)
{
  return (lasso_build_full_authnRequest(NULL,
					NULL,
					NULL,
					NULL,
					providerID,
					nameIDPolicy,
					forceAuthn,
					isPassive,
					protocolProfile,
					assertionConsumerServiceID,
					authnContextClassRefs,
					authnContextStatementRefs,
					authnContextComparison,
					relayState,
					proxyCount,
					idpList,
					consent));
}

LassoNode *lasso_build_full_authnRequest(const xmlChar *requestID,
					 const xmlChar *majorVersion,
					 const xmlChar *minorVersion,
					 const xmlChar *issueInstant,
					 const xmlChar *providerID,
					 const xmlChar *nameIDPolicy,
					 const xmlChar *forceAuthn,
					 const xmlChar *isPassive,
					 const xmlChar *protocolProfile,
					 const xmlChar *assertionConsumerServiceID,
					 const xmlChar **authnContextClassRefs,
					 const xmlChar **authnContextStatementRefs,
					 const xmlChar *authnContextComparison,
					 const xmlChar *relayState,
					 const xmlChar *proxyCount,
					 const xmlChar **idpList,
					 const xmlChar *consent)
{
  LassoNode  *request;

  // build AuthnRequest class
  request = lasso_lib_authn_request_new();

  if (requestID != NULL) {
    lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					       requestID);
  }
  else {
    lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					       (const xmlChar *)lasso_build_unique_id(32));
  }

  if (majorVersion != NULL) {
    lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  majorVersion);
  }
  else {
    lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  lassoLibMajorVersion);
  }

  if (minorVersion != NULL) {
    lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						  minorVersion);
  }
  else {
    lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						  lassoLibMinorVersion);
  }

  if (issueInstant != NULL) {
    lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						   issueInstant);
  }
  else {
    lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						   lasso_get_current_time());
  }

  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request),
					 providerID);

  if(nameIDPolicy != NULL) {
    lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(request), nameIDPolicy);
  }
  
  if(forceAuthn != NULL) {
    lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(request), forceAuthn);
  }
  
  if(isPassive != NULL) {
    lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(request), isPassive);
  }

  if(protocolProfile != NULL) {
    lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(request), protocolProfile);
  }
  
  if(assertionConsumerServiceID != NULL) {
    lasso_lib_authn_request_set_assertionConsumerServiceID(LASSO_LIB_AUTHN_REQUEST(request),
							   assertionConsumerServiceID);
  }
  
  if(relayState != NULL) {
    lasso_lib_authn_request_set_relayState(LASSO_LIB_AUTHN_REQUEST(request), relayState);
  }
  
  if(consent != NULL) {
    lasso_lib_authn_request_set_consent(LASSO_LIB_AUTHN_REQUEST(request), consent);
  }

  return (request);
}


LassoNode *lasso_build_full_authnResponse(LassoNode     *request,
					  const xmlChar *providerID)
{
     LassoNode *response;

     response = lasso_lib_authn_response_new();
     
     lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  (const xmlChar *)lasso_build_unique_id(32));
     lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lassoLibMajorVersion);     
     lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), 
						   lassoLibMinorVersion);
     lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						    lasso_get_current_time());

     lasso_lib_authn_response_set_providerID(response, providerID);

     return(response);
}

LassoNode *lasso_build_full_response(LassoNode     *request,
				     const xmlChar *providerID)
{
     LassoNode *response;

     response = lasso_samlp_response_new();

     lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  (const xmlChar *)lasso_build_unique_id(32));
     lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lassoSamlMajorVersion);     
     lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), 
						   lassoSamlMinorVersion);
     lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						    lasso_get_current_time());

     return(response);
}

LassoNode *lasso_build_assertion(const xmlChar *inResponseTo,
				 const xmlChar *issuer)
{
     LassoNode *assertion, *subject;

     assertion = lasso_lib_assertion_new();

     lasso_saml_assertion_set_assertionID(LASSO_SAML_ASSERTION(assertion),
					  (const xmlChar *)lasso_build_unique_id(32));
     lasso_saml_assertion_set_majorVersion(LASSO_SAML_ASSERTION(assertion),
					   lassoLibMajorVersion);
     lasso_saml_assertion_set_minorVersion(LASSO_SAML_ASSERTION(assertion),
					   lassoLibMajorVersion);
     lasso_saml_assertion_set_issueInstance(LASSO_SAML_ASSERTION(assertion),
					    lasso_get_current_time());

     lasso_lib_assertion_set_inResponseTo(LASSO_LIB_ASSERTION(assertion),
					  inResponseTo);

     lasso_saml_assertion_set_issuer(LASSO_SAML_ASSERTION(assertion),
				     issuer);

     return(assertion);
}

LassoNode *lasso_build_authenticationStatement(const xmlChar *authenticationMethod,
					       LassoNode     *nameIdentifier,
					       LassoNode     *idpProvidedNameIdentifier)
{
     LassoNode *statement, *subject;

     statement = lasso_saml_authentication_statement_new();

     lasso_saml_authentication_statement_set_authenticationMethod(LASSO_SAML_AUTHENTICATION_STATEMENT(statement), authenticationMethod);
     
     lasso_saml_authentication_statement_set_authenticationInstant(LASSO_SAML_AUTHENTICATION_STATEMENT(statement), lasso_get_current_time());

     subject = lasso_saml_subject_new();

     lasso_saml_subject_set_nameIdentifier(LASSO_SAML_SUBJECT(subject),
					   LASSO_SAML_NAME_IDENTIFIER(nameIdentifier));

     lasso_saml_subject_statement_abstract_set_subject(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(statement),
						       LASSO_SAML_SUBJECT(subject));

     return(statement);
}
