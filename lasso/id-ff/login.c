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

#include <lasso/protocols/request.h>
#include <lasso/protocols/response.h>
#include <lasso/protocols/artifact.h>
#include <lasso/protocols/authn_response.h>

#include <lasso/environs/login.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_login_build_authn_request_msg(LassoLogin *login)
{
  LassoProvider *provider, *remote_provider;
  xmlChar *request_protocolProfile, *url, *query;
  gchar *msg;
  gboolean must_sign;
  
  provider = LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server);
  must_sign = xmlStrEqual(lasso_node_get_child_content(provider->metadata, "AuthnRequestsSigned", NULL), "true");
  
  /* export request depending on the request ProtocolProfile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(provider);
  if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
    /* GET -> query */
    remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
						LASSO_PROFILE_CONTEXT(login)->remote_providerID);
    url = lasso_provider_get_singleSignOnServiceUrl(remote_provider);
    if (must_sign) {
      query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(login)->request,
					 LASSO_PROFILE_CONTEXT(login)->server->signature_method,
					 LASSO_PROFILE_CONTEXT(login)->server->private_key);
    }
    else {
      query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(login)->request, 0, NULL);
    }
    /* alloc msg_url (+2 for the ? and \0) */
    LASSO_PROFILE_CONTEXT(login)->msg_url = (gchar *) g_new(gchar, strlen(url) + strlen(query) + 2);
    g_sprintf(LASSO_PROFILE_CONTEXT(login)->msg_url, "%s?%s", url, query);
    g_free(url);
    g_free(query);
  }
  else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
    /* POST -> formular */
    printf("TODO - export the AuthnRequest in a formular\n");
  }
  
  return (0);
}

gint
lasso_login_build_authn_response_msg(LassoLogin  *login,
				     gint         authentication_result,
				     const gchar *authenticationMethod,
				     const gchar *reauthenticateOnOrAfter)
{
  LassoUser *user;
  LassoIdentity *identity;
  gchar     *msg = g_new(gchar, 1024), *samlArt;
  xmlChar   *nameIDPolicy, *relayState, *providerID;
  xmlChar   *assertionHandle, *identityProviderSuccinctID;
  LassoNode *assertion=NULL, *authentication_statement, *idpProvidedNameIdentifier;

  /* ProtocolProfile must be BrwsPost */
  if (login->protocolProfile != lassoLoginProtocolPorfileBrwsPost) {
    return (-1);
  }

  providerID = lasso_provider_get_providerID(LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server));

  /* federation */
  /* verify if a user context exists else create it */
  if (LASSO_PROFILE_CONTEXT(login)->user == NULL) {
    LASSO_PROFILE_CONTEXT(login)->user = lasso_user_new("");
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
    printf("DEBUG - NameIDPolicy is federated\n");
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

  /* fill the response with the assertion */
  if (identity != NULL && authentication_result == 1) {
    printf("DEBUG - an identity found, so build an assertion\n");
    assertion = lasso_assertion_new(providerID,
				    lasso_node_get_attr_value(LASSO_NODE(LASSO_PROFILE_CONTEXT(login)->request), "RequestID"));
    authentication_statement = lasso_authentication_statement_new(authenticationMethod,
								  reauthenticateOnOrAfter,
								  identity->remote_nameIdentifier,
								  identity->local_nameIdentifier);
    lasso_saml_assertion_add_authenticationStatement(LASSO_SAML_ASSERTION(assertion),
						     LASSO_SAML_AUTHENTICATION_STATEMENT(authentication_statement));
    lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
				       LASSO_PROFILE_CONTEXT(login)->server->signature_method,
				       LASSO_PROFILE_CONTEXT(login)->server->private_key,
				       LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server)->certificate);
    lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE_CONTEXT(login)->response),
				       assertion);
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
  
  return (0);
}

gint
lasso_login_init_authn_request(LassoLogin  *login,
			       const gchar *remote_providerID)
{
  LassoProvider *server;

  server = LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server);
  LASSO_PROFILE_CONTEXT(login)->request = lasso_authn_request_new(lasso_provider_get_providerID(server));
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = remote_providerID;

  if (LASSO_PROFILE_CONTEXT(login)->request == NULL) {
    return (-1);
  }

  return (0);
}

gint
lasso_login_init_from_authn_request_msg(LassoLogin *login,
					gchar      *authn_request_msg,
					gint        authn_request_method)
{
  LassoServer *server;
  LassoProvider *sp;
  gchar *protocolProfile;
  gboolean  must_verify_signature, signature_status;

  server = LASSO_PROFILE_CONTEXT(login)->server;

  /* rebuild request */
  switch (authn_request_method) {
  case lassoHttpMethodGet:
  case lassoHttpMethodRedirect:
    /* LibAuthnRequest send by method GET */
    LASSO_PROFILE_CONTEXT(login)->request = lasso_authn_request_new_from_query(authn_request_msg);
    break;
  case lassoHttpMethodPost:
    /* TODO LibAuthnRequest send by method POST */
    break;
  }

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
    break;
  case lassoLoginProtocolPorfileBrwsArt:
    /* create SamlpResponse */
    LASSO_PROFILE_CONTEXT(login)->response = lasso_response_new();
    break;
  }

  /* get SP ProviderID */
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
										 "ProviderID", NULL);
  sp = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
				 LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  /* Is authnRequest signed ? */
  must_verify_signature = xmlStrEqual(lasso_node_get_child_content(sp->metadata, "AuthnRequestsSigned", NULL), "true");

  /* verify request signature */
  if (must_verify_signature) {
    switch (authn_request_method) {
    case lassoHttpMethodGet:
    case lassoHttpMethodRedirect:
      signature_status = lasso_query_verify_signature(authn_request_msg,
						      sp->public_key,
						      LASSO_PROFILE_CONTEXT(login)->server->private_key);
      break;
    case lassoHttpMethodPost:
      signature_status = lasso_node_verify_signature(LASSO_PROFILE_CONTEXT(login)->request,
						     sp->certificate);
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
lasso_login_init_request(LassoLogin *login,
			 xmlChar    *response_msg,
			 gint        response_method)
{
  xmlChar *artifact;

  /* rebuild response (artifact) */
  switch (response_method = 1) {
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

  /* create SamlpRequest */
  artifact = lasso_artifact_get_samlArt(LASSO_ARTIFACT(LASSO_PROFILE_CONTEXT(login)->response));
  LASSO_PROFILE_CONTEXT(login)->request = lasso_request_new(artifact);
  xmlFree(artifact);

  return (0);
}

gint
lasso_login_init_response(LassoLogin *login,
			  xmlChar    *response_msg,
			  gint        response_method)
{
  // TODO

  return (0);
}

gint
lasso_handle_authn_response_msg(LassoLogin *login,
				gchar      *authn_response_msg)
{
  LassoNode *assertion, *status, *statusCode;
  LassoProvider *idp;
  gchar *statusCode_value;

  LASSO_PROFILE_CONTEXT(login)->response = lasso_authn_response_new_from_export(authn_response_msg, 0);
  assertion = lasso_node_get_child(LASSO_PROFILE_CONTEXT(login)->response,
				   "Assertion",
				   lassoLibHRef);
  idp = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
				  LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  if (assertion != NULL) {
    lasso_node_verify_signature(assertion, idp->certificate);
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

gboolean
lasso_login_must_authenticate(LassoLogin *login,
			      gboolean    is_user_authenticated)
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
  if ((forceAuthn == TRUE || is_user_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (is_user_authenticated == FALSE && isPassive == TRUE) {
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
