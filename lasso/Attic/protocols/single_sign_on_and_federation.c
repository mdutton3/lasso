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
			       gint           forceAuthn,
			       gint           isPassive,
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
  LassoNode *request, *authn_context, *scoping;
  gint i;
  gboolean authn_context_ok = FALSE;

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
  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request), providerID);

  /* NameIDPolicy */
  if (nameIDPolicy != NULL) {
    lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(request), nameIDPolicy);
  }
  
  /* ForceAuthn */
  lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(request), forceAuthn);
  
  /* IsPassive */
  lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(request), isPassive);

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
  if (authnContextClassRefs != NULL) {
    if (authnContextClassRefs->len > 0) {
      authn_context_ok = TRUE;
    }
  }
  if (!authn_context_ok && authnContextStatementRefs != NULL) {
    if (authnContextStatementRefs->len > 0) {
      authn_context_ok = TRUE;
    }
  }

  if (authn_context_ok) {
    /* create a new AuthnContext instance */
    authn_context = lasso_lib_request_authn_context_new();
    /* AuthnContextClassRefs */
    if (authnContextClassRefs != NULL) {
      if (authnContextClassRefs->len > 0) {
	for(i=0; i<authnContextClassRefs->len; i++) {
	  lasso_lib_request_authn_context_add_authnContextClassRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								   lasso_g_ptr_array_index(authnContextClassRefs, i));
	}
      }
    }
    /* AuthnContextStatementRefs */
    if (authnContextStatementRefs != NULL) {
      if (authnContextStatementRefs->len > 0) {
	for(i=0; i<authnContextStatementRefs->len; i++) {
	  lasso_lib_request_authn_context_add_authnContextStatementRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								       lasso_g_ptr_array_index(authnContextStatementRefs, i));
	}
      }
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
lasso_authn_request_create(const xmlChar *providerID,
			   const xmlChar *nameIDPolicy,
			   gint           forceAuthn,
			   gint           isPassive,
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
  lareq->type = lassoProtocolTypeAuthnRequest;
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
			    const xmlChar *certificate,
			    gboolean       isAuthenticated)
{
  lassoAuthnResponse *lares;
  GData       *gd;
  gboolean     forceAuthn = FALSE;
  gboolean     isPassive = TRUE;
  const gchar *authnContextComparison = lassoLibAuthnContextComparisonExact;
  gint         proxyCount = 0;

  lares = g_malloc(sizeof(lassoAuthnResponse));
  lares->type = lassoProtocolTypeAuthnResponse;
  lares->request_query = query;
  lares->public_key = public_key;
  lares->private_key = private_key;
  lares->certificate = certificate;

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
    /* if forceAuthn exists, convert it into integer */
    if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "forceAuthn"), 0) != NULL) {
      forceAuthn = atoi(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0));
    }
    /* if isPassive exists, convert it into integer */
    if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0) != NULL) {
      isPassive = atoi(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0));
    }
    /* if isPassive exists, convert it into integer */
    if (g_datalist_get_data(&gd, "AuthnContextClassRef") != NULL ||
	g_datalist_get_data(&gd, "AuthnContextStatementRef") != NULL) {
      if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AuthnContextComparison"), 0) != NULL) {
	authnContextComparison = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AuthnContextComparison"), 0);
      }
    }
    
    lares->request_node = lasso_authn_request_build_full(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstance"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIDPolicy"), 0),
							 forceAuthn,
							 isPassive,
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProtocolProfile"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AssertionConsumerServiceID"), 0),
							 (GPtrArray *)g_datalist_get_data(&gd, "AuthnContextClassRef"),
							 (GPtrArray *)g_datalist_get_data(&gd, "AuthnContextStatementRef"),
							 authnContextComparison,
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0),
							 proxyCount,
							 (GPtrArray *)g_datalist_get_data(&gd, "IDPList"),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0));
  }
  
  lasso_node_dump(lares->request_node, "iso-8859-1", 1);

  if (lares->node == NULL) {
    return (NULL);
  }

  if (xmlStrEqual((xmlChar *)lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0), "true")) {
    lares->isPassive = TRUE;
  }
  else {
    lares->isPassive = FALSE;
  }

  if (xmlStrEqual(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0), "true")){
    forceAuthn = TRUE;
  }
  else {
    forceAuthn = FALSE;
  }
  /* we can freed gd */
  g_datalist_clear(&gd);

  lares->mustAuthenticate = FALSE;
  if ((forceAuthn == TRUE || isAuthenticated == FALSE) && lares->isPassive == FALSE) {
    lares->mustAuthenticate = TRUE;
  }

  return (lares);
}

gint
lasso_authn_response_init(lassoAuthnResponse *lares,
			  const xmlChar      *providerID,
			  gboolean            authentication_result)
{
  LassoNode *response;
  LassoNode *status, *status_code;
  xmlChar *content;
  gint status_code_value = 1;

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
  
  /* StatusCode value */
  if (authentication_result == TRUE) {
    content = lasso_node_get_content(lasso_node_get_child(lares->request_node, "NameIDPolicy"));
    if (xmlStrEqual(content, "none") || content == NULL) {
      printf("Aucun NameIDPolicy ou None\n");
      status_code_value = 0;
    }
    xmlFree(content);
  }
  else
    status_code_value = 0;

  /* Add Status */
  status = lasso_samlp_status_new();
  status_code = lasso_samlp_status_code_new();
  if (status_code_value == 0)
    lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code), lassoSamlStatusCodeRequestDenied);
  else
    lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code), lassoSamlStatusCodeSuccess);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status), LASSO_SAMLP_STATUS_CODE(status_code));
  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response), LASSO_SAMLP_STATUS(status));

  /* RelayState */
  content = lasso_node_get_content(lasso_node_get_child(lares->request_node, "RelayState"));
  if (content != NULL) {
    lasso_lib_authn_response_set_relayState(LASSO_LIB_AUTHN_RESPONSE(response), content);
  }
  xmlFree(content);

  /* InResponseTo */
  content = xmlNodeGetContent((xmlNodePtr)lasso_node_get_attr(lares->request_node, "RequestID"));
  if (content != NULL) {
    lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   content);
  }
  xmlFree(content);

  lares->node = response;
}

gint
lasso_authn_response_add_assertion(lassoAuthnResponse *lares,
				   LassoNode *assertion)
{
  xmlDocPtr doc;
  LassoNode *signature;

  /* FIXME : Signature */
  doc = xmlNewDoc("1.0"); // <---
  xmlAddChild((xmlNodePtr)doc, LASSO_NODE_GET_CLASS(lares->node)->get_xmlNode(lares->node));

  signature = lasso_ds_signature_new(doc, xmlSecTransformRsaSha1Id);
  lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
				     LASSO_DS_SIGNATURE(signature)); 
  lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(lares->node),
				     LASSO_LIB_ASSERTION(assertion));
  lasso_ds_signature_sign(LASSO_DS_SIGNATURE(signature),
			  lares->private_key,
			  lares->certificate);

  lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(lares->node),
				     LASSO_LIB_ASSERTION(assertion));

  return (0);
}

LassoNode *
lasso_assertion_build(gpointer *lares,
		      const xmlChar *issuer)
{
  LassoNode *assertion, *statement, *subject;
  LassoAttr *requestID;
  xmlChar *content;

  g_assert(((lassoAuthnResponse *)lares)->type == lassoProtocolTypeAuthnResponse ||
	   ((lassoAuthnResponse *)lares)->type == lassoProtocolTypeResponse);

  if (((lassoAuthnResponse *)lares)->type == lassoProtocolTypeAuthnResponse) {
    assertion = lasso_lib_assertion_new();
  }
  else {
    assertion = lasso_saml_assertion_new();
  }

  lasso_saml_assertion_set_assertionID(LASSO_SAML_ASSERTION(assertion),
				       (const xmlChar *)lasso_build_unique_id(32));
  lasso_saml_assertion_set_majorVersion(LASSO_SAML_ASSERTION(assertion),
					lassoLibMajorVersion);
  lasso_saml_assertion_set_minorVersion(LASSO_SAML_ASSERTION(assertion),
					lassoLibMajorVersion);
  lasso_saml_assertion_set_issueInstance(LASSO_SAML_ASSERTION(assertion),
					 lasso_get_current_time());
  
  lasso_saml_assertion_set_issuer(LASSO_SAML_ASSERTION(assertion),
				  issuer);

  /* InResponseTo */
  requestID = lasso_node_get_attr(((lassoAuthnResponse *)lares)->request_node,
				  "RequestID");
  content = xmlNodeGetContent((xmlNodePtr)requestID);
  if (content != NULL) {
    lasso_lib_assertion_set_inResponseTo(LASSO_LIB_ASSERTION(assertion),
					 content);
  }
  xmlFree(content);

  return (assertion);
}

gint
lasso_assertion_add_authenticationStatement(LassoNode *assertion,
					    LassoNode *statement)
{
  lasso_saml_assertion_add_authenticationStatement(LASSO_SAML_ASSERTION(assertion),
						   LASSO_SAML_AUTHENTICATION_STATEMENT(statement));
  return (1);
}

LassoNode *
lasso_authentication_statement_build(const xmlChar *authenticationMethod,
				     const xmlChar *sessionIndex,
				     const xmlChar *reauthenticateOnOrAfter,
				     xmlChar       *nameIdentifier,
				     const xmlChar *nameQualifier,
				     const xmlChar *format,
				     xmlChar       *idp_nameIdentifier,
				     const xmlChar *idp_nameQualifier,
				     const xmlChar *idp_format,
				     const xmlChar *confirmationMethod)
{
  LassoNode *statement, *subject;
  LassoNode *identifier, *idp_identifier, *subject_confirmation;

  statement = lasso_lib_authentication_statement_new();
  lasso_saml_authentication_statement_set_authenticationMethod(LASSO_SAML_AUTHENTICATION_STATEMENT(statement),
							       authenticationMethod);
  lasso_saml_authentication_statement_set_authenticationInstant(LASSO_SAML_AUTHENTICATION_STATEMENT(statement),
								lasso_get_current_time());
  if (sessionIndex != NULL) {
    lasso_lib_authentication_statement_set_sessionIndex(LASSO_LIB_AUTHENTICATION_STATEMENT(statement),
							sessionIndex);
  }
  lasso_lib_authentication_statement_set_reauthenticateOnOrAfter(LASSO_LIB_AUTHENTICATION_STATEMENT(statement),
								 reauthenticateOnOrAfter);

  subject = lasso_lib_subject_new();
  identifier = lasso_saml_name_identifier_new(nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier),
					       nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier),
					format);
  lasso_saml_subject_set_nameIdentifier(LASSO_SAML_SUBJECT(subject),
					LASSO_SAML_NAME_IDENTIFIER(identifier));
  idp_identifier = lasso_lib_idp_provided_name_identifier_new(idp_nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(idp_identifier),
					       idp_nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(idp_identifier),
					idp_format);
  lasso_saml_subject_set_nameIdentifier(LASSO_SAML_SUBJECT(subject),
					LASSO_SAML_NAME_IDENTIFIER(idp_identifier));
  lasso_lib_subject_set_idpProvidedNameIdentifier(LASSO_LIB_SUBJECT(subject),
						  LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idp_identifier));
  subject_confirmation = lasso_saml_subject_confirmation_new();
  lasso_saml_subject_confirmation_set_subjectConfirmationMethod(LASSO_SAML_SUBJECT_CONFIRMATION(subject_confirmation),
								confirmationMethod);
  lasso_saml_subject_set_subjectConfirmation(LASSO_SAML_SUBJECT(subject),
					     LASSO_SAML_SUBJECT_CONFIRMATION(subject_confirmation));

  if (confirmationMethod != NULL) {
    lasso_saml_subject_statement_abstract_set_subject(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(statement),
						      LASSO_SAML_SUBJECT(subject));
  }

  return (statement);
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
