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

/*****************************************************************************/
/* AuthnRequest                                                              */
/*****************************************************************************/

static LassoNode *
lasso_authn_request_build_full(const xmlChar *requestID,
			       const xmlChar *majorVersion,
			       const xmlChar *minorVersion,
			       const xmlChar *issueInstant,
			       const xmlChar *providerID,
			       const xmlChar *nameIDPolicy,
			       const xmlChar *forceAuthn,
			       const xmlChar *isPassive,
			       const xmlChar *protocolProfile,
			       const xmlChar *assertionConsumerServiceID,
			       GPtrArray     *authnContextClassRefs,
			       GPtrArray     *authnContextStatementRefs,
			       const xmlChar *authnContextComparison,
			       const xmlChar *relayState,
			       gint           proxyCount,
			       GPtrArray     *idpList,
			       const xmlChar *consent)
{
  LassoNode  *request, *authn_context, *scoping;
  gint i;

  /* create a new AuthnRequestinstance */
  request = lasso_lib_authn_request_new();
  /* RequestID */
  if (requestID != NULL) {
    lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					       requestID);
  }
  else {
    lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					       (const xmlChar *)lasso_build_unique_id(32));
  }

  /* MajorVersion */
  if (majorVersion != NULL) {
    lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  majorVersion);
  }
  else {
    lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  lassoLibMajorVersion);
  }

  /* MinorVersion */
  if (minorVersion != NULL) {
    lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						  minorVersion);
  }
  else {
    lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						  lassoLibMinorVersion);
  }

  /* IssueInstant */
  if (issueInstant != NULL) {
    lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						   issueInstant);
  }
  else {
    lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						   lasso_get_current_time());
  }

  /* ProviderID */
  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request),
					 providerID);

  /* NameIDPolicy */
  if (nameIDPolicy != NULL) {
    lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(request), nameIDPolicy);
  }
  
  /* ForceAuthn */
  if (forceAuthn != NULL) {
    lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(request), forceAuthn);
  }
  
  /* IsPassive */
  if (isPassive != NULL) {
    lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(request), isPassive);
  }

  /* ProtocolProfile */
  if (protocolProfile != NULL) {
    lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(request), protocolProfile);
  }
  
  /* AssertionConsumerServiceID */
  if (assertionConsumerServiceID != NULL) {
    lasso_lib_authn_request_set_assertionConsumerServiceID(LASSO_LIB_AUTHN_REQUEST(request),
							   assertionConsumerServiceID);
  }

  /* AuthnContext */
  if (authnContextClassRefs != NULL || authnContextStatementRefs != NULL) {
    /* create a new AuthnContext instance */
    authn_context = lasso_lib_request_authn_context_new();
    /* AuthnContextClassRefs */
    if (authnContextClassRefs != NULL) {
      for(i=0; i<authnContextClassRefs->len; i++) {
	lasso_lib_request_authn_context_add_authnContextClassRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								 lasso_g_ptr_array_index(authnContextClassRefs, i));
      }
    }
    /* AuthnContextStatementRefs */
    for(i=0; i<authnContextStatementRefs->len; i++) {
      lasso_lib_request_authn_context_add_authnContextStatementRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								   lasso_g_ptr_array_index(authnContextStatementRefs, i));
    }
    /* AuthnContextComparison */
    if (authnContextComparison != NULL) {
      lasso_lib_request_authn_context_set_authnContextComparison(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								 authnContextComparison);
    }
    /* Add AuthnContext to AuthnRequest */
    lasso_lib_authn_request_set_requestAuthnContext(LASSO_LIB_AUTHN_REQUEST(request),
						    LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context));
  }

  /* RelayState */
  if (relayState != NULL) {
    lasso_lib_authn_request_set_relayState(LASSO_LIB_AUTHN_REQUEST(request), relayState);
  }

  /* Scoping */
  if (proxyCount > 0) {
    /* create a new Scoping instance */
    scoping = lasso_lib_scoping_new();
    /* ProxyCount */
    lasso_lib_scoping_set_proxyCount(LASSO_LIB_SCOPING(scoping), proxyCount);
    lasso_lib_authn_request_set_scoping(LASSO_LIB_AUTHN_REQUEST(request),
					LASSO_LIB_SCOPING(scoping));
  }

  /* consent */
  if (consent != NULL) {
    lasso_lib_authn_request_set_consent(LASSO_LIB_AUTHN_REQUEST(request), consent);
  }

  return (request);
}

lassoAuthnRequest *
lasso_authn_request_build(const xmlChar *providerID,
			  const xmlChar *nameIDPolicy,
			  const xmlChar *forceAuthn,
			  const xmlChar *isPassive,
			  const xmlChar *protocolProfile,
			  const xmlChar *assertionConsumerServiceID,
			  GPtrArray     *authnContextClassRefs,
			  GPtrArray     *authnContextStatementRefs,
			  const xmlChar *authnContextComparison,
			  const xmlChar *relayState,
			  gint           proxyCount,
			  GPtrArray     *idpList,
			  const xmlChar *consent)
{
  lassoAuthnRequest *lareq;

  lareq = g_malloc(sizeof(lassoAuthnRequest));
  lareq->node = lasso_authn_request_build_full(NULL,
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
					       consent);
  return (lareq);
}

/*****************************************************************************/
/* AuthnResponse                                                             */
/*****************************************************************************/

lassoAuthnResponse *
lasso_authn_response_create(xmlChar       *query,
			    gboolean       verifySignature,
			    const xmlChar *public_key,
			    const xmlChar *private_key,
			    gboolean       isAuthenticated,
			    gboolean      *isPassive,
			    gboolean      *mustAuthenticate,
			    GPtrArray     *authenticationMethods,
			    xmlChar       *authnContextComparison)
{
  lassoAuthnResponse *lares;
  GData     *gd;
  gboolean   forceAuthn = FALSE;
  gint       proxyCount = 0;

  lares = g_malloc(sizeof(lassoAuthnResponse));
  lares->request_query = query;

  if (verifySignature == TRUE) {
    if (lasso_str_verify(query, public_key, private_key) != 1) {
      return (NULL);
    }
  }

  gd = lasso_query_to_dict(query);

  if (gd != NULL) {
    /* if ProxyCount exists, convert it into integer */
    if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProxyCount"), 0) != NULL) {
      proxyCount = atoi(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProxyCount"), 0));
    }
    lares->node = lasso_authn_request_build_full(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstance"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIDPolicy"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProtocolProfile"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AssertionConsumerServiceID"), 0),
						 (GPtrArray *)g_datalist_get_data(&gd, "AuthnContextClassRef"),
						 (GPtrArray *)g_datalist_get_data(&gd, "AuthnContextStatementRef"),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AuthnContextComparison"), 0),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0),
						 proxyCount,
						 (GPtrArray *)g_datalist_get_data(&gd, "IDPList"),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0));
  }
  
  lasso_node_dump(lares->node, "iso-8859-1", 1);

  if (lares->node == NULL) {
    return (NULL);
  }

  if (xmlStrEqual((xmlChar *)lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0), "true")) {
    *isPassive = TRUE;
  }
  else {
    *isPassive = FALSE;
  }

  if (xmlStrEqual(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0), "true")){
    forceAuthn = TRUE;
  }
  else {
    forceAuthn = FALSE;
  }
  /* we can freed gd */
  g_datalist_clear(&gd);

  *mustAuthenticate = FALSE;
  //if ((forceAuthn == TRUE) || (isAuthenticated == TRUE)) {
  if (forceAuthn == TRUE && isAuthenticated == TRUE && *isPassive != TRUE) {
    *mustAuthenticate = TRUE;
  }

  return (lares);
}

gint
lasso_authn_response_build(lassoAuthnResponse *lares,
			   const xmlChar      *providerID,
			   gboolean            authentication_result,
			   GPtrArray          *nameIdentifiers)
{
  LassoNode *response;
  xmlChar *content;
  gint status_code = 0;

  response = lasso_lib_authn_response_new();
  
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       (const xmlChar *)lasso_build_unique_id(32));
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lassoLibMajorVersion);     
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), 
						 lassoLibMinorVersion);
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  lasso_get_current_time());
  
  lasso_lib_authn_response_set_providerID(LASSO_LIB_AUTHN_RESPONSE(response), providerID);
  
  if (authentication_result == TRUE) {
    content = lasso_node_get_content(lasso_node_get_child(lares->request_node, "NameIDPolicy"));
    if (content == NULL) {
      printf("Pas de NameIDPolicy\n");
      status_code = 1;
    }
    else
      printf("NameIDPolicy = %s\n", content);
    xmlFree(content);
  }
  else
    status_code = 0;

  content = lasso_node_get_content(lasso_node_get_child(lares->request_node, "RelayState"));
  if (content != NULL) {
    lasso_lib_authn_response_set_relayState(LASSO_LIB_AUTHN_RESPONSE(response), content);
  }
  xmlFree(content);

  lares->node = response;
}

LassoNode *
lasso_response_build_full(LassoNode     *request,
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
  
  return (response);
}

LassoNode *
lasso_assertion_build(const xmlChar *inResponseTo,
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
  
  return (assertion);
}

LassoNode *
lasso_authenticationStatement_build(const xmlChar *authenticationMethod,
				    LassoNode     *nameIdentifier,
				    LassoNode     *idpProvidedNameIdentifier)
{
  LassoNode *statement, *subject;
  
  statement = lasso_lib_authentication_statement_new();
  
  lasso_saml_authentication_statement_set_authenticationMethod(LASSO_SAML_AUTHENTICATION_STATEMENT(statement),
							       authenticationMethod);
  
  lasso_saml_authentication_statement_set_authenticationInstant(LASSO_SAML_AUTHENTICATION_STATEMENT(statement),
								lasso_get_current_time());
  
  subject = lasso_lib_subject_new();
  
  lasso_saml_subject_set_nameIdentifier(LASSO_SAML_SUBJECT(subject),
					LASSO_SAML_NAME_IDENTIFIER(nameIdentifier));
  
  lasso_lib_subject_set_idpProvidedNameIdentifier(LASSO_LIB_SUBJECT(subject),
						  LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idpProvidedNameIdentifier));
  
  lasso_saml_subject_statement_abstract_set_subject(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(statement),
						    LASSO_SAML_SUBJECT(subject));
  
  return (statement);
}
