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

#include <lasso/environs/login.h>

#include <lasso/protocols/artifact.h>
#include <lasso/protocols/provider.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

gint
lasso_login_process_federation(LassoLogin *login)
{
  LassoIdentity *identity;
  xmlChar       *nameIDPolicy;
  LassoNode     *idpProvidedNameIdentifier;

  /* verify if a user context exists else create it */
  if (LASSO_PROFILE_CONTEXT(login)->user == NULL) {
    LASSO_PROFILE_CONTEXT(login)->user = lasso_user_new();
  }
  identity = lasso_user_get_identity(LASSO_PROFILE_CONTEXT(login)->user,
				     LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
					      "NameIDPolicy", NULL);
  printf("NameIDPolicy %s\n", nameIDPolicy);
  if (nameIDPolicy == NULL || xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone)) {
    if (identity == NULL) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						lassoLibStatusCodeFederationDoesNotExist);
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)) {
    debug(DEBUG, "NameIDPolicy is federated");
    if (identity == NULL) {
      identity = lasso_identity_new(LASSO_PROFILE_CONTEXT(login)->remote_providerID);
      idpProvidedNameIdentifier = lasso_lib_idp_provided_name_identifier_new(lasso_build_unique_id(32));
      /* TODO: set nameQualifier and Format */
      lasso_identity_set_local_nameIdentifier(identity, idpProvidedNameIdentifier);
      lasso_user_add_identity(LASSO_PROFILE_CONTEXT(login)->user,
			      LASSO_PROFILE_CONTEXT(login)->remote_providerID,
			      identity);
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    // TODO
  }

  return (0);
}

gint
lasso_login_add_response_assertion(LassoLogin    *login,
				   LassoIdentity *identity,
				   const gchar   *authenticationMethod,
				   const gchar   *reauthenticateOnOrAfter)
{
  xmlChar *providerID;
  LassoNode *assertion=NULL, *authentication_statement;
  xmlChar *ni, *idp_ni;

  providerID = lasso_provider_get_providerID(LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server));
  assertion = lasso_assertion_new(providerID,
				  lasso_node_get_attr_value(LASSO_NODE(LASSO_PROFILE_CONTEXT(login)->request), "RequestID"));
  authentication_statement = lasso_authentication_statement_new(authenticationMethod,
								reauthenticateOnOrAfter,
								identity->remote_nameIdentifier,
								identity->local_nameIdentifier);
  ni = lasso_node_get_child_content(LASSO_NODE(authentication_statement), "NameIdentifier", NULL);
  idp_ni = lasso_node_get_child_content(LASSO_NODE(authentication_statement), "IDPProvidedNameIdentifier", NULL);
  /* store NameIdentifier */
  if (xmlStrEqual(ni, idp_ni)) {
    login->nameIdentifier = idp_ni;
    xmlFree(ni);
  }
  else {
    login->nameIdentifier = ni;
    xmlFree(idp_ni);
  }
  lasso_saml_assertion_add_authenticationStatement(LASSO_SAML_ASSERTION(assertion),
						   LASSO_SAML_AUTHENTICATION_STATEMENT(authentication_statement));
  lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
				     LASSO_PROFILE_CONTEXT(login)->server->signature_method,
				     LASSO_PROFILE_CONTEXT(login)->server->private_key,
				     LASSO_PROFILE_CONTEXT(login)->server->certificate);
  lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE_CONTEXT(login)->response),
				     assertion);

  return (0);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_login_build_artifact_msg(LassoLogin       *login,
			       gint              authentication_result,
			       const gchar      *authenticationMethod,
			       const gchar      *reauthenticateOnOrAfter,
			       lassoHttpMethods  method)
{
  LassoIdentity *identity;
  LassoProvider *remote_provider;

  gchar   *b64_samlArt, *samlArt, *url;
  xmlChar *relayState;
  xmlChar *assertionHandle, *identityProviderSuccinctID;
  xmlChar *providerID;

  /* ProtocolProfile must be BrwsArt */
  if (login->protocolProfile != lassoLoginProtocolPorfileBrwsArt) {
    return (-1);
  }

  /* federation */
  lasso_login_process_federation(login);
  identity = lasso_user_get_identity(LASSO_PROFILE_CONTEXT(login)->user,
				     LASSO_PROFILE_CONTEXT(login)->remote_providerID);

  /* fill the response with the assertion */
  if (identity != NULL && authentication_result == 1) {
    printf("DEBUG - an identity found, so build an assertion\n");
    lasso_login_add_response_assertion(login,
				       identity,
				       authenticationMethod,
				       reauthenticateOnOrAfter);
  }
  else {
    printf("No identity or login failed !!!\n");
    if (authentication_result == 0) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						lassoSamlStatusCodeRequestDenied);
    }
  }
  /* save response dump */
  login->response_dump = lasso_node_export(LASSO_PROFILE_CONTEXT(login)->response);

  providerID = lasso_provider_get_providerID(LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server));
  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  /* build artifact infos */
  /* liberty-idff-bindings-profiles-v1.2.pdf p.25 */
  url = lasso_provider_get_assertionConsumerServiceURL(remote_provider);
  samlArt = g_new(gchar, 2+20+20+1);
  identityProviderSuccinctID = lasso_str_hash(providerID,
					      LASSO_PROFILE_CONTEXT(login)->server->private_key);
  xmlFree(providerID);
  assertionHandle = lasso_build_random_sequence(20);
  sprintf(samlArt, "%c%c%s%s", 0, 3, identityProviderSuccinctID, assertionHandle);
  g_free(assertionHandle);
  xmlFree(identityProviderSuccinctID);
  b64_samlArt = xmlSecBase64Encode(samlArt, 42, 0);
  g_free(samlArt);
  relayState = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
					    "RelayState", NULL);

  switch (method) {
  case lassoHttpMethodRedirect:
    LASSO_PROFILE_CONTEXT(login)->msg_url = g_new(gchar, 1024+1);
    sprintf(LASSO_PROFILE_CONTEXT(login)->msg_url, "%s?SAMLArt=%s", url, b64_samlArt);
    if (relayState != NULL) {
      sprintf(LASSO_PROFILE_CONTEXT(login)->msg_url, "%s&RelayState=%s",
	      LASSO_PROFILE_CONTEXT(login)->msg_url, relayState);
    }
    break;
  case lassoHttpMethodPost:
    LASSO_PROFILE_CONTEXT(login)->msg_url  = g_strdup(url);
    LASSO_PROFILE_CONTEXT(login)->msg_body = g_strdup(b64_samlArt);
    if (relayState != NULL) {
      login->msg_relayState = g_strdup(relayState);
    }
    break;
  }
  xmlFree(url);
  xmlFree(b64_samlArt);
  xmlFree(relayState);
  
  return (0);
}

gint
lasso_login_build_authn_request_msg(LassoLogin *login)
{
  LassoProvider *provider, *remote_provider;
  xmlChar *request_protocolProfile, *url, *query, *lareq;
  gboolean must_sign;
  
  provider = LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server);
  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  must_sign = xmlStrEqual(lasso_node_get_child_content(provider->metadata, "AuthnRequestsSigned", NULL), "true");
  /* export request depending on the request ProtocolProfile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(remote_provider);
  /* get SingleSignOnServiceURL metadata */
  url = lasso_provider_get_singleSignOnServiceURL(remote_provider);
  if (url == NULL) return (-1);

  if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
    /* GET -> query */
    if (must_sign) {
      query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(login)->request,
					 LASSO_PROFILE_CONTEXT(login)->server->signature_method,
					 LASSO_PROFILE_CONTEXT(login)->server->private_key);
    }
    else {
      query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(login)->request, 0, NULL);
    }
    if (query == NULL) return (-2);
    /* alloc msg_url (+2 for the ? and \0) */
    LASSO_PROFILE_CONTEXT(login)->msg_url = (gchar *) g_new(gchar, strlen(url) + strlen(query) + 2);
    g_sprintf(LASSO_PROFILE_CONTEXT(login)->msg_url, "%s?%s", url, query);
    LASSO_PROFILE_CONTEXT(login)->msg_body = NULL;
    g_free(query);
  }
  else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
    /* POST -> formular */
    lareq = lasso_node_export_to_base64(LASSO_PROFILE_CONTEXT(login)->request);
    if (lareq == NULL) return (-2);
    LASSO_PROFILE_CONTEXT(login)->msg_url = g_strdup(url);
    LASSO_PROFILE_CONTEXT(login)->msg_body = lareq;
  }
  g_free(url);
  
  return (0);
}

gint
lasso_login_build_authn_response_msg(LassoLogin  *login,
				     gint         authentication_result,
				     const gchar *authenticationMethod,
				     const gchar *reauthenticateOnOrAfter)
{
  LassoProvider *remote_provider;
  LassoIdentity *identity;

  /* ProtocolProfile must be BrwsPost */
  if (login->protocolProfile != lassoLoginProtocolPorfileBrwsPost) {
    return (-1);
  }
  
  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);

  /* federation */
  lasso_login_process_federation(login);
  identity = lasso_user_get_identity(LASSO_PROFILE_CONTEXT(login)->user,
				     LASSO_PROFILE_CONTEXT(login)->remote_providerID);

  /* fill the response with the assertion */
  if (identity != NULL && authentication_result == 1) {
    printf("DEBUG - an identity found, so build an assertion\n");
    lasso_login_add_response_assertion(login,
				       identity,
				       authenticationMethod,
				       reauthenticateOnOrAfter);
  }
  else {
    printf("No identity or login failed !!!\n");
    if (authentication_result == 0) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						lassoSamlStatusCodeRequestDenied);
    }
  }
  
  /* return an authnResponse (base64 encoded) */
  LASSO_PROFILE_CONTEXT(login)->msg_body = lasso_node_export_to_base64(LASSO_PROFILE_CONTEXT(login)->response);
  LASSO_PROFILE_CONTEXT(login)->msg_url  = lasso_provider_get_assertionConsumerServiceURL(remote_provider);

  return (0);
}

gint
lasso_login_build_request_msg(LassoLogin *login)
{
  LassoProvider *remote_provider;

  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  LASSO_PROFILE_CONTEXT(login)->msg_body = lasso_node_export_to_soap(LASSO_PROFILE_CONTEXT(login)->request);
  LASSO_PROFILE_CONTEXT(login)->msg_url = lasso_provider_get_soapEndpoint(remote_provider);
  return (0);
}

gchar*
lasso_login_dump(LassoLogin *login)
{
  LassoNode *node;
  gchar *parent_dump, *dump, *str;

  parent_dump = lasso_profile_context_dump(LASSO_PROFILE_CONTEXT(login), "LassoLogin");
  node = lasso_node_new_from_dump(parent_dump);
  g_free(parent_dump);

  if (login->protocolProfile > 0) {
    str = g_new0(gchar, 6);
    sprintf(str, "%d", login->protocolProfile);
    LASSO_NODE_GET_CLASS(node)->new_child(node, "ProtocolProfile", str, FALSE);
    g_free(str);
  }

  if (login->assertionArtifact != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "AssertionArtifact", login->assertionArtifact, FALSE);
  }
  if (login->response_dump != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "ResponseDump", login->response_dump, FALSE);
  }
  if (login->msg_relayState != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "MsgRelayState", login->msg_relayState, FALSE);
  }

  dump = lasso_node_export(node);
  lasso_node_destroy(node);

  return (dump);
}

gint
lasso_login_init_authn_request(LassoLogin  *login,
			       const gchar *remote_providerID)
{
  LassoProvider *server;

  server = LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server);
  LASSO_PROFILE_CONTEXT(login)->request = lasso_authn_request_new(lasso_provider_get_providerID(server));
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeAuthnRequest;
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = g_strdup(remote_providerID);

  if (LASSO_PROFILE_CONTEXT(login)->request == NULL) {
    return (-1);
  }

  return (0);
}

gint
lasso_login_init_from_authn_request_msg(LassoLogin       *login,
					gchar            *authn_request_msg,
					lassoHttpMethods  authn_request_method)
{
  LassoServer *server;
  LassoProvider *remote_provider;
  gchar *protocolProfile;
  gboolean  must_verify_signature, signature_status;

  server = LASSO_PROFILE_CONTEXT(login)->server;

  /* rebuild request */
  switch (authn_request_method) {
  case lassoHttpMethodGet:
  case lassoHttpMethodRedirect:
    /* LibAuthnRequest send by method GET */
    LASSO_PROFILE_CONTEXT(login)->request = lasso_authn_request_new_from_export(authn_request_msg,
										lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodPost:
    /* TODO LibAuthnRequest send by method POST */
    break;
  }
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeAuthnRequest;

  /* get ProtocolProfile */
  protocolProfile = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
						 "ProtocolProfile", NULL);
  if (protocolProfile == NULL) {
    login->protocolProfile = lassoLoginProtocolPorfileBrwsArt;
  }
  else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileBrwsArt)) {
    login->protocolProfile = lassoLoginProtocolPorfileBrwsArt;
  }
  else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileBrwsPost)) {
    login->protocolProfile = lassoLoginProtocolPorfileBrwsPost;
  }

  /* build response */
  switch (login->protocolProfile) {
  case lassoLoginProtocolPorfileBrwsPost:
    /* create LibAuthnResponse */
    LASSO_PROFILE_CONTEXT(login)->response = lasso_authn_response_new(lasso_provider_get_providerID(LASSO_PROVIDER(server)),
								      LASSO_PROFILE_CONTEXT(login)->request);
    LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeAuthnResponse;
    break;
  case lassoLoginProtocolPorfileBrwsArt:
    /* create SamlpResponse */
    LASSO_PROFILE_CONTEXT(login)->response = lasso_response_new();
    LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeResponse;
    break;
  }

  /* get remote ProviderID */
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
										 "ProviderID", NULL);
  printf("remote_providerID = %s\n", LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  /* Is authnRequest signed ? */
  must_verify_signature = xmlStrEqual(lasso_node_get_child_content(remote_provider->metadata, "AuthnRequestsSigned", NULL), "true");

  /* verify request signature */
  if (must_verify_signature) {
    switch (authn_request_method) {
    case lassoHttpMethodGet:
    case lassoHttpMethodRedirect:
      debug(INFO, "Query signature has been verified\n");
      signature_status = lasso_query_verify_signature(authn_request_msg,
						      remote_provider->public_key,
						      LASSO_PROFILE_CONTEXT(login)->server->private_key);
      break;
    case lassoHttpMethodPost:
      signature_status = lasso_node_verify_signature(LASSO_PROFILE_CONTEXT(login)->request,
						     remote_provider->ca_certificate);
      break;
    }
    
    /* Modify StatusCode if signature is not OK */
    if (signature_status == 0 || signature_status == 2) {
      switch (signature_status) {
      case 0: // Invalid Signature
	lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						  lassoLibStatusCodeInvalidSignature);
	break;
      case 2: // Unsigned AuthnRequest
	lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						  lassoLibStatusCodeUnsignedAuthnRequest);
	break;
      }
      return (-1);
    }
  }
  return (0);
}

gint
lasso_login_init_request(LassoLogin       *login,
			 gchar            *response_msg,
			 lassoHttpMethods  response_method,
			 const gchar      *remote_providerID)
{
  xmlChar *artifact;

  LASSO_PROFILE_CONTEXT(login)->remote_providerID = g_strdup(remote_providerID);

  /* rebuild response (artifact) */
  switch (response_method) {
  case lassoHttpMethodGet:
  case lassoHttpMethodRedirect:
    /* artifact by REDIRECT */
    LASSO_PROFILE_CONTEXT(login)->response = lasso_artifact_new_from_query(response_msg);
    break;
  case lassoHttpMethodPost:
    /* artifact by POST */
    LASSO_PROFILE_CONTEXT(login)->response = lasso_artifact_new_from_lares(response_msg, NULL);
    break;
  }
  LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeArtifact;

  /* create SamlpRequest */
  artifact = lasso_artifact_get_samlArt(LASSO_ARTIFACT(LASSO_PROFILE_CONTEXT(login)->response));
  LASSO_PROFILE_CONTEXT(login)->request = lasso_request_new(artifact);
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeRequest;
  xmlFree(artifact);

  return (0);
}

gint
lasso_login_process_authn_response_msg(LassoLogin *login,
				       gchar      *authn_response_msg)
{
  LassoNode *assertion, *status, *statusCode;
  LassoProvider *idp;
  gchar *statusCode_value;

  LASSO_PROFILE_CONTEXT(login)->response = lasso_authn_response_new_from_export(authn_response_msg,
										lassoNodeExportTypeBase64);
  LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeAuthnResponse;

  assertion = lasso_node_get_child(LASSO_PROFILE_CONTEXT(login)->response,
				   "Assertion",
				   lassoLibHRef);
  idp = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
				  LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  if (assertion != NULL) {
    lasso_node_verify_signature(assertion, idp->ca_certificate);
  }
  else {
    return (-1);
  }
  status = lasso_node_get_child(LASSO_PROFILE_CONTEXT(login)->response,
				"Status",
				lassoSamlProtocolHRef);
  if (status != NULL) {
    statusCode = lasso_node_get_child(status,
				  "StatusCode",
				  lassoSamlProtocolHRef);
    
    if (statusCode) {
      statusCode_value = lasso_node_get_content(statusCode);
      if (xmlStrEqual(statusCode_value, lassoSamlStatusCodeSuccess)) {
	return (-4);
      }
    }
    else {
      return (-3);
    }
  }
  else {
    return (-2);
  }
  return (0);
}

gint
lasso_login_process_request_msg(LassoLogin *login,
				gchar      *request_msg)
{
  LassoNode *node;

  node = lasso_node_new_from_dump(request_msg);
 
  // TODO : rebuild request in login->request and set login->request_type
  login->assertionArtifact = lasso_node_get_child_content(node, "AssertionArtifact", lassoSamlProtocolHRef);
  lasso_node_destroy(node);

  return (0);
}

gboolean
lasso_login_must_authenticate(LassoLogin *login)
{
  gboolean  must_authenticate = TRUE;
  gboolean  isPassive = TRUE;
  gboolean  forceAuthn = FALSE;

  /* verify if the user must be authenticated or not */
  if (xmlStrEqual(lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request, "IsPassive", NULL), "false")) {
    isPassive = FALSE;
  }

  if (xmlStrEqual(lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request, "ForceAuthn", NULL), "true")) {
    forceAuthn = TRUE;
  }

  /* complex test to login process */
  if ((forceAuthn == TRUE || LASSO_PROFILE_CONTEXT(login)->user == NULL) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (LASSO_PROFILE_CONTEXT(login)->user == NULL && isPassive == TRUE) {
    lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
					      lassoLibStatusCodeNoPassive);
    must_authenticate = FALSE;
  }

  return (must_authenticate);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_login_instance_init(LassoLogin *login)
{
  login->protocolProfile = 0;
  login->assertionArtifact = NULL;
  login->nameIdentifier    = NULL;
  login->response_dump     = NULL;
  login->msg_relayState    = NULL;
}

static void
lasso_login_class_init(LassoLoginClass *class)
{
}

GType lasso_login_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLoginClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_login_class_init,
      NULL,
      NULL,
      sizeof(LassoLogin),
      0,
      (GInstanceInitFunc) lasso_login_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoLogin",
				       &this_info, 0);
  }
  return this_type;
}

LassoProfileContext*
lasso_login_new(LassoServer *server,
		LassoUser   *user)
{
  LassoProfileContext *login;

  login = LASSO_PROFILE_CONTEXT(g_object_new(LASSO_TYPE_LOGIN,
					     "server", server,
					     "user", user,
					     NULL));
  
  return (login);
}

LassoProfileContext*
lasso_login_new_from_dump(LassoServer *server,
			  LassoUser   *user,
			  gchar       *dump)
{
  LassoProfileContext *login;
  LassoNode *node_dump;

  login = LASSO_PROFILE_CONTEXT(g_object_new(LASSO_TYPE_LOGIN,
					     "server", server,
					     "user", user,
					     NULL));
  
  node_dump = lasso_node_new_from_dump(dump);
  login->remote_providerID = lasso_node_get_child_content(node_dump, "RemoteProviderID", NULL);
  login->request = NULL;

  lasso_node_destroy(node_dump);

  return (login);
}
