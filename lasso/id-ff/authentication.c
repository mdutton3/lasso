/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/samlp_response.h>
#include <lasso/protocols/request.h>
#include <lasso/protocols/response.h>
#include <lasso/protocols/authn_response.h>
#include <lasso/environs/authentication.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_authentication_build_request(LassoAuthentication *authn)
{
  LassoProvider *provider;
  xmlChar *request_protocolProfile, *url, *query;
  gchar *str;
  
  provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(authn)->server,
				       LASSO_PROFILE_CONTEXT(authn)->local_providerID);
  if (provider == NULL) {
    return (NULL);
  }  

  /* build the request object */
  LASSO_PROFILE_CONTEXT(authn)->request = lasso_authn_request_new(LASSO_PROFILE_CONTEXT(authn)->local_providerID);

  /* optional values */
/*   if (protocolProfile != NULL) { */
/*     lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request), */
/* 						protocolProfile); */
/*   } */
/*   if (nameIDPolicy != NULL) { */
/*     lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request), */
/* 					     nameIDPolicy); */
/*   } */
/*   lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request), isPassive); */
/*   lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request), forceAuthn); */
  
  /* export request depending on the request protocol profile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(provider);
  if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
    url = lasso_provider_get_singleSignOnServiceUrl(provider);
    query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(authn)->request, 1, NULL);
    str = (gchar *) g_new(gchar, strlen(url) + strlen(query) + 2); // +2 for the ? character and the end line character
    g_sprintf(str, "%s?%s", url, query);
    
    LASSO_PROFILE_CONTEXT(authn)->request_protocol_method = lassoProfileContextMethodGet;
  }
  else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
    printf("TODO - export the AuthnRequest in a formular\n");
  }
  
  return (str);
}

xmlChar*
lasso_authentication_process_artifact(LassoAuthentication *authn,
				      gchar               *artifact)
{
  LASSO_PROFILE_CONTEXT(authn)->request = lasso_request_new(artifact);
  return (lasso_node_export_to_soap(LASSO_PROFILE_CONTEXT(authn)->request));
}

gboolean
lasso_authentication_process_response(LassoAuthentication *authn,
				      xmlChar             *response)
{
  LassoNode *statusCode, *assertion;
  LassoNode *nameIdentifier, *idpProvidedNameIdentifier;
  char *artifact, *statusCodeValue;

  printf("DEBUG - POST response, process the authnResponse\n");
  LASSO_PROFILE_CONTEXT(authn)->response = LASSO_NODE(lasso_authn_response_new_from_export(response, 0));
    
  /* process the status code value */
  statusCode = lasso_node_get_child(LASSO_PROFILE_CONTEXT(authn)->response, "StatusCode", NULL);
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value");
  if(strcmp(statusCodeValue, lassoSamlStatusCodeSuccess))
    return(FALSE);
  
  /* process the assertion */
  assertion = lasso_node_get_child(LASSO_PROFILE_CONTEXT(authn)->response, "Assertion", NULL);
  if(!assertion)
    return(FALSE);
  
  /* set the name identifiers */
  nameIdentifier = lasso_node_get_child(assertion, "NameIdentifier", NULL);
  printf("name identifier %s(%s)\n", lasso_node_get_content(nameIdentifier), lasso_node_export(nameIdentifier));
  
  idpProvidedNameIdentifier = lasso_node_get_child(assertion, "IDPProvidedNameIdentifier", NULL);
  
  return(TRUE);
}

gboolean
lasso_authentication_process_request(LassoAuthentication *authn,
				     gchar               *request,
				     gint                 request_method,
				     gboolean             is_authenticated)
{
  LassoProvider *provider;
  xmlChar  *protocolProfile;
  gboolean  must_authenticate = TRUE;
  gboolean  isPassive = TRUE;
  gboolean  forceAuthn = FALSE;
  gboolean  signature_status;

  switch (request_method) {
  case lassoProfileContextMethodGet:
    LASSO_PROFILE_CONTEXT(authn)->request = LASSO_NODE(lasso_authn_request_new_from_query(request));
    LASSO_PROFILE_CONTEXT(authn)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request,
										 "ProviderID", NULL);

    protocolProfile = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request, "ProtocolProfile", NULL);
    if (xmlStrEqual(protocolProfile, lassoLibProtocolProfilePost)) {
      LASSO_PROFILE_CONTEXT(authn)->response = lasso_authn_response_new(LASSO_PROFILE_CONTEXT(authn)->local_providerID,
									LASSO_PROFILE_CONTEXT(authn)->request);
    }
    else {
      LASSO_PROFILE_CONTEXT(authn)->response = lasso_response_new();
    }

    provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(authn)->server,
					 LASSO_PROFILE_CONTEXT(authn)->remote_providerID);
    if (xmlStrEqual(lasso_node_get_child_content(provider->metadata, "AuthnRequestsSigned", NULL), "true")) {
      signature_status = lasso_query_verify_signature(request,
						      provider->public_key,
						      LASSO_PROFILE_CONTEXT(authn)->server->private_key);
      /* Status & StatusCode */
      if (signature_status == 0 || signature_status == 2) {
	switch (signature_status) {
	case 0: // Invalid Signature
	  lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
						    lassoLibStatusCodeInvalidSignature);
	  break;
	case 2: // Unsigned AuthnRequest
	  lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
						    lassoLibStatusCodeUnsignedAuthnRequest);
	  break;
	}
      }
    }
    break;
  case lassoProfileContextMethodPost:
    printf("TODO - lasso_authentication_process_authnRequest() - implement the parsing of the post request\n");
    break;
  default:
    printf("ERROR - lasso_authentication_process_authnRequest() - Unknown protocol method\n");
  }
  
  /* verify if the user must be authenticated or not */
  if (xmlStrEqual(lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request, "IsPassive", NULL), "false")) {
    isPassive = FALSE;
  }

  if (xmlStrEqual(lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request, "ForceAuthn", NULL), "true")) {
    forceAuthn = TRUE;
  }

  /* complex test to authentication process */
  if ((forceAuthn == TRUE || is_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (is_authenticated == FALSE && isPassive == TRUE) {
    lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
					      lassoLibStatusCodeNoPassive);
    must_authenticate = FALSE;
  }

  return (must_authenticate);
}

gchar *
lasso_authentication_process_authentication_result(LassoAuthentication *authn,
						   gint                 authentication_result,
						   const gchar         *authentication_method)
{
  LassoUser *user;
  xmlChar   *str, *nameIDPolicy, *protocolProfile;
  LassoNode *assertion, *authentication_statement, *idpProvidedNameIdentifier;
  
  LassoIdentity *identity;

  /* process the federation policy */
  /* TODO : implement a get identity */
  
  printf("process authentication\n");
  /* verify if a user context exists */
  if (LASSO_PROFILE_CONTEXT(authn)->user == NULL) {
    LASSO_PROFILE_CONTEXT(authn)->user = lasso_user_new();
  }
  
  identity = lasso_user_find_identity(LASSO_PROFILE_CONTEXT(authn)->user,
				      LASSO_PROFILE_CONTEXT(authn)->remote_providerID);
  nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request,
					      "NameIDPolicy", NULL);
  printf("NameIDPolicy %s\n", nameIDPolicy);
  if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone)) {
    if (identity == NULL) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
						lassoLibStatusCodeFederationDoesNotExist);
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)) {
    printf("DEBUG - NameIDPolicy is federated\n");
    if (identity == NULL) {
      identity = lasso_identity_new(LASSO_PROFILE_CONTEXT(authn)->remote_providerID);
      idpProvidedNameIdentifier = LASSO_NODE(lasso_lib_idp_provided_name_identifier_new(lasso_build_unique_id(32)));
      lasso_identity_set_local_name_identifier(identity, idpProvidedNameIdentifier);
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    
  }
  
  /* fill the response with the assertion */
  if (identity) {
    printf("DEBUG - an identity found, so build an assertion\n");
    //assertion = lasso_assertion_new(authn->local_providerID, lasso_node_get_attr_value(LASSO_NODE(authn->request),
    //									       "RequestID"));
    //authentication_statement = lasso_authentication_statement_new(authentication_method,
    //							"TODO",
    //							nameIdentifier,
    //							"TODO",
    //							"TODO",
    //							idpProvidedNameIdentifier,
    //							"TODO",
    //							"TODO");
    //lasso_saml_assertion_add_authenticationStatement(assertion,
    //					   authentication_statement);
    //lasso_samlp_response_add_assertion(authn->response, assertion);
  }
  
  /* return a response message */
  protocolProfile = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request,
						 "ProtocolProfile", NULL);
  if (xmlStrEqual(protocolProfile, lassoLibProtocolProfilePost)) {
    str = lasso_node_export_to_base64(LASSO_PROFILE_CONTEXT(authn)->response);
  }
  else {
    printf("DEBUG - return a artifact message\n");
  }
  
  return(str);
}

void
lasso_authentication_set_forceAuthn(LassoAuthentication *authn,
				    const xmlChar       *forceAuthn)
{
  lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request),
					 forceAuthn);
}

void
lasso_authentication_set_isPassive(LassoAuthentication *authn,
				   gboolean            *isPassive)
{
  lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request),
					isPassive);
}

void
lasso_authentication_set_nameIDPolicy(LassoAuthentication *authn,
				      const xmlChar       *nameIDPolicy)
{
  lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request),
					   nameIDPolicy);
}

void
lasso_authentication_set_protocolProfile(LassoAuthentication *authn,
					 const xmlChar       *protocolProfile)
{
  lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE_CONTEXT(authn)->request),
					      protocolProfile);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authentication_instance_init(LassoAuthentication *authn)
{
}

static void
lasso_authentication_class_init(LassoAuthenticationClass *class)
{
}

GType lasso_authentication_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthenticationClass),
      NULL,
      NULL,
/*       (GClassInitFunc) lasso_authentication_class_init, */
      NULL,
      NULL,
      NULL,
      sizeof(LassoAuthentication),
      0,
/*       (GInstanceInitFunc) lasso_authentication_instance_init, */
      NULL,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoAuthentication",
				       &this_info, 0);
  }
  return this_type;
}

LassoProfileContext*
lasso_authentication_new(LassoServer *server,
			 LassoUser   *user,
			 gchar       *local_providerID,
			 gchar       *remote_providerID)
{
  /* load the ProviderID name or a reference to the provider ? */
  g_return_val_if_fail(local_providerID != NULL, NULL);
  g_return_val_if_fail(remote_providerID != NULL, NULL);

  LassoProfileContext *authn;

  authn = LASSO_PROFILE_CONTEXT(g_object_new(LASSO_TYPE_AUTHENTICATION,
					     "server", server,
					     "user", user,
					     "local_providerID", local_providerID,
					     "remote_providerID", remote_providerID,
					     NULL));

  return (authn);
}
