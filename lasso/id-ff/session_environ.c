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
#include <lasso/environs/session_environ.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

static void
set_response_status(LassoNode     *response,
		    const xmlChar *statusCodeValue)
{
  LassoNode *status, *status_code;

  status = lasso_samlp_status_new();

  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    statusCodeValue);

  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));

  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				  LASSO_SAMLP_STATUS(status));
  lasso_node_destroy(status_code);
  lasso_node_destroy(status);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_session_environ_build_authn_request(LassoSessionEnviron *session,
					  const gchar         *protocolProfile,
					  gboolean             isPassive,
					  gboolean             forceAuthn,
					  const gchar         *nameIDPolicy)
{
  LassoProvider *provider;
  xmlChar *request_protocolProfile, *url, *query;
  gchar *str;
  
  provider = lasso_server_environ_get_provider(session->server,
					       session->local_providerID);
  if (provider == NULL) {
    return (NULL);
  }  

  /* build the request object */
  session->request = LASSO_NODE(lasso_authn_request_new(session->local_providerID));
  /* optional values */
  if (protocolProfile != NULL) {
    lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(session->request),
						protocolProfile);
  }
  if (nameIDPolicy != NULL) {
    lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(session->request),
					     nameIDPolicy);
  }
  lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(session->request), isPassive);
  lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(session->request), forceAuthn);
  
  /* export request depending on the request protocol profile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(provider);
  if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
    url = lasso_provider_get_singleSignOnServiceUrl(provider);
    query = lasso_node_export_to_query(session->request, 1, NULL);
    str = (gchar *) malloc(strlen(url) + strlen(query) + 2); // +2 for the ? character and the end line character
    sprintf(str, "%s?%s", url, query);
    
    session->request_protocol_method = lasso_protocol_method_get;
  }
  else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
    printf("TODO - export the AuthnRequest in a formular\n");
  }
  
  return (str);
}

xmlChar*
lasso_session_environ_process_artifact(LassoSessionEnviron *session,
				       gchar               *artifact)
{
  session->request = lasso_request_new(artifact);
  return (lasso_node_export_to_soap(session->request));
}

gboolean
lasso_session_environ_process_authn_response(LassoSessionEnviron *session,
					     xmlChar             *response)
{
  LassoNode *statusCode, *assertion;
  LassoNode *nameIdentifier, *idpProvidedNameIdentifier;
  char *artifact, *statusCodeValue;

  printf("DEBUG - POST response, process the authnResponse\n");
  session->response = LASSO_NODE(lasso_authn_response_new_from_export(response, 0));
    
  /* process the status code value */
  statusCode = lasso_node_get_child(session->response, "StatusCode", NULL);
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value");
  if(strcmp(statusCodeValue, lassoSamlStatusCodeSuccess))
    return(FALSE);
  
  /* process the assertion */
  assertion = lasso_node_get_child(session->response, "Assertion", NULL);
  if(!assertion)
    return(FALSE);
  
  /* set the name identifiers */
  nameIdentifier = lasso_node_get_child(assertion, "NameIdentifier", NULL);
  printf("name identifier %s(%s)\n", lasso_node_get_content(nameIdentifier), lasso_node_export(nameIdentifier));
  
  idpProvidedNameIdentifier = lasso_node_get_child(assertion, "IDPProvidedNameIdentifier", NULL);
  
  return(TRUE);
}

gboolean
lasso_session_environ_process_authn_request(LassoSessionEnviron *session,
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
  case lasso_protocol_method_get:
    session->request = LASSO_NODE(lasso_authn_request_new_from_query(request));
    session->peer_providerID = lasso_node_get_child_content(session->request, "ProviderID", NULL);

    protocolProfile = lasso_node_get_child_content(session->request, "ProtocolProfile", NULL);
    if (xmlStrEqual(protocolProfile, lassoLibProtocolProfilePost)) {
      session->response = lasso_authn_response_new(session->local_providerID, session->request);
    }
    else {
      session->response = lasso_response_new();
    }

    provider = lasso_server_environ_get_provider(session->server, session->peer_providerID);
    if (xmlStrEqual(lasso_node_get_child_content(provider->metadata, "AuthnRequestsSigned", NULL), "true")) {
      signature_status = lasso_query_verify_signature(request,
						      provider->public_key,
						      session->server->private_key);
      /* Status & StatusCode */
      if (signature_status == 0 || signature_status == 2) {
	switch (signature_status) {
	case 0:
	  set_response_status(session->response, lassoLibStatusCodeInvalidSignature);
	  break;
	case 2:
	  set_response_status(session->response, lassoLibStatusCodeUnsignedAuthnRequest);
	  break;
	}
      }
    }
    break;
  case lasso_protocol_method_post:
    printf("TODO - lasso_session_environ_process_authnRequest() - implement the parsing of the post request\n");
    break;
  default:
    printf("ERROR - lasso_session_environ_process_authnRequest() - Unknown protocol method\n");
  }
  
  /* verify if the user must be authenticated or not */
  if (xmlStrEqual(lasso_node_get_child_content(session->request, "IsPassive", NULL), "false")) {
    isPassive = FALSE;
  }

  if (xmlStrEqual(lasso_node_get_child_content(session->request, "ForceAuthn", NULL), "true")) {
    forceAuthn = TRUE;
  }

  /* complex test to authentication process */
  if ((forceAuthn == TRUE || is_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (is_authenticated == FALSE && isPassive == TRUE) {
    set_response_status(session->response, lassoLibStatusCodeNoPassive);
    must_authenticate = FALSE;
  }

  return (must_authenticate);
}

gchar *
lasso_session_environ_process_authentication(LassoSessionEnviron *session,
					     gint                 authentication_result,
					     const gchar         *authentication_method)
{
  LassoUserEnviron *user;
  xmlChar          *str, *nameIDPolicy, *protocolProfile;
  LassoNode        *assertion, *authentication_statement, *idpProvidedNameIdentifier;
  
  LassoIdentity *identity;

  /* process the federation policy */
  /* TODO : implement a get identity */
  
  printf("process authentication\n");
  /* verify if a user environ exists */
  if (session->user == NULL) {
    session->user = lasso_user_environ_new();
  }
  
  identity = lasso_user_environ_find_identity(session->user, session->peer_providerID);
  nameIDPolicy = lasso_node_get_child_content(session->request, "NameIDPolicy", NULL);
  printf("NameIDPolicy %s\n", nameIDPolicy);
  if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone)) {
    if (identity == NULL) {
      set_response_status(session->response, lassoLibStatusCodeFederationDoesNotExist);
    }
  }
  else if (!strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)) {
    printf("DEBUG - NameIDPolicy is federated\n");
    if (identity == NULL) {
      identity = lasso_identity_new(session->peer_providerID);
      idpProvidedNameIdentifier = LASSO_NODE(lasso_lib_idp_provided_name_identifier_new(lasso_build_unique_id(32)));
      lasso_identity_set_local_name_identifier(identity, idpProvidedNameIdentifier);
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    
  }
  
  /* fill the response with the assertion */
  if (identity) {
    printf("DEBUG - an identity found, so build an assertion\n");
    //assertion = lasso_assertion_new(session->local_providerID, lasso_node_get_attr_value(LASSO_NODE(session->request),
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
    //lasso_samlp_response_add_assertion(session->response, assertion);
  }
  
  /* return a response message */
  protocolProfile = lasso_node_get_child_content(session->request, "ProtocolProfile", NULL);
  if (xmlStrEqual(protocolProfile, lassoLibProtocolProfilePost)) {
    str = lasso_node_export_to_base64(session->response);
  }
  else {
    printf("DEBUG - return a artifact message\n");
  }
  
  return(str);
}

gint
lasso_session_environ_set_local_providerID(LassoSessionEnviron *session,
					   gchar               *providerID)
{
  if (session->local_providerID) {
    free(session->local_providerID);
  }
  session->local_providerID = (char *)malloc(strlen(providerID)+1);
  strcpy(session->local_providerID, providerID);
  
  return (1);
}

gint
lasso_session_environ_set_peer_providerID(LassoSessionEnviron *session,
					  gchar               *providerID)
{
  if (session->peer_providerID) {
    free(session->peer_providerID);
  }
  session->peer_providerID = (char *)malloc(strlen(providerID)+1);
  strcpy(session->peer_providerID, providerID);
  
  return (1);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_session_environ_instance_init(LassoSessionEnviron *session)
{
  session->user = NULL;
  session->message = NULL;
  session->request  = NULL;
  session->response = NULL;
  session->local_providerID = NULL;
  session->peer_providerID = NULL;
  session->request_protocol_method = 0;
}

static void
lasso_session_environ_class_init(LassoSessionEnvironClass *class)
{
}

GType lasso_session_environ_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSessionEnvironClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_session_environ_class_init,
      NULL,
      NULL,
      sizeof(LassoSessionEnviron),
      0,
      (GInstanceInitFunc) lasso_session_environ_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoSessionEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoSessionEnviron*
lasso_session_environ_new(LassoServerEnviron *server,
			  LassoUserEnviron   *user,
			  gchar              *local_providerID,
			  gchar              *peer_providerID)
{
  /* load the ProviderID name or a reference to the provider ? */
  g_return_val_if_fail(local_providerID != NULL, NULL);
  g_return_val_if_fail(peer_providerID != NULL, NULL);

  LassoSessionEnviron *session;

  session = g_object_new(LASSO_TYPE_SESSION_ENVIRON, NULL);

  session->server = server;

  if (user != NULL) {
    session->user = user;
  }

  lasso_session_environ_set_local_providerID(session, local_providerID);
  lasso_session_environ_set_peer_providerID(session, peer_providerID);

  return (session);
}
