 /* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <string.h>
#include <glib/gprintf.h>
#include <xmlsec/base64.h>

#include <lasso/xml/errors.h>

#include <lasso/environs/login.h>

#include <lasso/protocols/artifact.h>
#include <lasso/protocols/provider.h>
#include <lasso/protocols/elements/authentication_statement.h>

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

static gchar*
lasso_login_get_assertion_nameIdentifier(LassoNode *assertion)
{
  xmlChar *ni, *idp_ni;

  ni = lasso_node_get_child_content(assertion, "NameIdentifier", NULL);
  idp_ni = lasso_node_get_child_content(assertion, "IDPProvidedNameIdentifier", NULL);

  if (xmlStrEqual(ni, idp_ni) && idp_ni != NULL) {
    xmlFree(ni);
    return (idp_ni);
  }
  else {
    xmlFree(idp_ni);
    if (ni != NULL) {
      return (ni);
    }
    else {
      debug(ERROR, "NameIdentifier value not found in AuthenticationStatement element.\n");
      return (NULL);
    }
  }
}

static gint
lasso_login_add_response_assertion(LassoLogin    *login,
				   LassoIdentity *identity,
				   const gchar   *authenticationMethod,
				   const gchar   *reauthenticateOnOrAfter)
{
  LassoNode *assertion = NULL, *authentication_statement;
  xmlChar *requestID;
  GError *err = NULL;
  gint ret = 0;

  requestID = lasso_node_get_attr_value(LASSO_NODE(LASSO_PROFILE_CONTEXT(login)->request),
					"RequestID", &err);

  if (requestID == NULL) {
    debug(ERROR, err->message);
    ret = err->code;
    g_error_free(err);
    return(ret);
  }

  assertion = lasso_assertion_new(LASSO_PROFILE_CONTEXT(login)->server->providerID,
				  requestID);
  xmlFree(requestID);
  authentication_statement = lasso_authentication_statement_new(authenticationMethod,
								reauthenticateOnOrAfter,
								LASSO_SAML_NAME_IDENTIFIER(identity->remote_nameIdentifier),
								LASSO_SAML_NAME_IDENTIFIER(identity->local_nameIdentifier));
  if (authentication_statement != NULL) {
    lasso_saml_assertion_add_authenticationStatement(LASSO_SAML_ASSERTION(assertion),
						     LASSO_SAML_AUTHENTICATION_STATEMENT(authentication_statement));
  }
  else {
    debug(ERROR, "Failed to build the AuthenticationStatement element of the Assertion.\n");
    lasso_node_destroy(assertion);
    return(-3);
  }
  /* store NameIdentifier */
  login->nameIdentifier = lasso_login_get_assertion_nameIdentifier(assertion);

  ret = lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
					   LASSO_PROFILE_CONTEXT(login)->server->signature_method,
					   LASSO_PROFILE_CONTEXT(login)->server->private_key,
					   LASSO_PROFILE_CONTEXT(login)->server->certificate);
  if (ret == 0) {
    lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE_CONTEXT(login)->response),
				       assertion);
  
    /* store assertion in user object */
    lasso_user_add_assertion(LASSO_PROFILE_CONTEXT(login)->user,
			     LASSO_PROFILE_CONTEXT(login)->remote_providerID,
			     lasso_node_copy(assertion));
  }

  lasso_node_destroy(authentication_statement);
  lasso_node_destroy(assertion);

  return (ret);
}

static gint
lasso_login_process_federation(LassoLogin *login)
{
  LassoIdentity *identity;
  LassoNode *nameIdentifier;
  xmlChar *nameIDPolicy;

  /* verify if a user context exists else create it */
  if (LASSO_PROFILE_CONTEXT(login)->user == NULL) {
    LASSO_PROFILE_CONTEXT(login)->user = lasso_user_new();
  }
  identity = lasso_user_get_identity(LASSO_PROFILE_CONTEXT(login)->user,
				     LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
					      "NameIDPolicy", NULL);
  if (nameIDPolicy == NULL || xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone)) {
    if (identity == NULL) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						lassoLibStatusCodeFederationDoesNotExist);
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)) {
    debug(DEBUG, "NameIDPolicy is federated\n");
    if (identity == NULL) {
      identity = lasso_identity_new(LASSO_PROFILE_CONTEXT(login)->remote_providerID);

      /* set local NameIdentifier in identity */
      nameIdentifier = lasso_saml_name_identifier_new(lasso_build_unique_id(32));
      lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier),
						   LASSO_PROFILE_CONTEXT(login)->server->providerID);
      lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier),
					    lassoLibNameIdentifierFormatFederated);
      lasso_identity_set_local_nameIdentifier(identity, nameIdentifier);
      lasso_node_destroy(nameIdentifier);

      lasso_user_add_identity(LASSO_PROFILE_CONTEXT(login)->user,
			      LASSO_PROFILE_CONTEXT(login)->remote_providerID,
			      identity);
    }
    else {
      debug(DEBUG, "An identity was found.\n");
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    /* TODO */
  }
  xmlFree(nameIDPolicy);

  return (0);
}

static gint
lasso_login_process_response_status_and_assertion(LassoLogin *login) {
  LassoNode *assertion = NULL, *status = NULL, *statusCode = NULL;
  LassoProvider *idp = NULL;
  gchar *statusCode_value = NULL;
  gint signature_check;
  gint ret = 0;
  GError *err = NULL;

  assertion = lasso_node_get_child(LASSO_PROFILE_CONTEXT(login)->response,
				   "Assertion",
				   lassoLibHRef);
  idp = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
				  LASSO_PROFILE_CONTEXT(login)->remote_providerID);

  if (assertion != NULL) {
    /* verify signature */
    if (idp->ca_certificate != NULL) {
      signature_check = lasso_node_verify_signature(assertion, idp->ca_certificate);
      if (signature_check < 0) {
	/* ret = -1 or -2 or -3 */
	ret = signature_check;
	goto done;
      }
    }

    /* store NameIdentifier */
    login->nameIdentifier = lasso_login_get_assertion_nameIdentifier(assertion);
    if (login->nameIdentifier == NULL) {
      debug(ERROR, "NameIdentifier element not found in Assertion.\n");
      ret = -4;
      goto done;
    }
  }

  /* check StatusCode value */
  status = lasso_node_get_child(LASSO_PROFILE_CONTEXT(login)->response,
				"Status", lassoSamlProtocolHRef);
  if (status == NULL) {
    debug(ERROR, "Status element not found in response.\n");
    ret = -9;
    goto done;
  }
  statusCode = lasso_node_get_child(status, "StatusCode", lassoSamlProtocolHRef);
    
  if (statusCode == NULL) {
    debug(ERROR, "StatusCode element not found in Status.\n");
    ret = -8;
    goto done;
  }
  statusCode_value = lasso_node_get_attr_value(statusCode, "Value", &err);
  if (err == NULL) {
    if (!xmlStrEqual(statusCode_value, lassoSamlStatusCodeSuccess)) {
      ret = -7;
    }
  }
  else {
    debug(ERROR, err->message);
    ret = err->code;
    g_error_free(err);
  }

 done:
  xmlFree(statusCode_value);
  lasso_node_destroy(statusCode);
  lasso_node_destroy(status);
  lasso_node_destroy(assertion);

  return (ret);
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

  if (method != lassoHttpMethodRedirect && method != lassoHttpMethodPost) {
    debug(ERROR, "Invalid HTTP method, it could be REDIRECT or POST\n.");
    return (-1);
  }

  /* ProtocolProfile must be BrwsArt */
  if (login->protocolProfile != lassoLoginProtocolProfileBrwsArt) {
    debug(WARNING, "Failed to build artifact message, an AuthnResponse is required by ProtocolProfile.\n");
    return (-2);
  }

  /* federation */
  lasso_login_process_federation(login);
  identity = lasso_user_get_identity(LASSO_PROFILE_CONTEXT(login)->user,
				     LASSO_PROFILE_CONTEXT(login)->remote_providerID);

  /* fill the response with the assertion */
  if (identity != NULL && authentication_result == 1) {
    debug(DEBUG, "An identity found, so build an assertion.\n");
    lasso_login_add_response_assertion(login,
				       identity,
				       authenticationMethod,
				       reauthenticateOnOrAfter);
  }
  else {
    debug(DEBUG, "No identity or login failed !!!\n");
    if (authentication_result == 0) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						lassoSamlStatusCodeRequestDenied);
    }
  }
  /* save response dump */
  login->response_dump = lasso_node_export_to_soap(LASSO_PROFILE_CONTEXT(login)->response);
  debug(DEBUG, "SOAP enveloped Samlp:response = %s\n", LASSO_LOGIN(login)->response_dump);

  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);
  /* build artifact infos */
  /* liberty-idff-bindings-profiles-v1.2.pdf p.25 */
  url = lasso_provider_get_assertionConsumerServiceURL(remote_provider);
  samlArt = g_new(gchar, 2+20+20+1);
  identityProviderSuccinctID = lasso_str_hash(LASSO_PROFILE_CONTEXT(login)->server->providerID,
					      LASSO_PROFILE_CONTEXT(login)->server->private_key);
  assertionHandle = lasso_build_random_sequence(20);
  sprintf(samlArt, "%c%c%s%s", 0, 3, identityProviderSuccinctID, assertionHandle);
  g_free(assertionHandle);
  xmlFree(identityProviderSuccinctID);
  b64_samlArt = (gchar *)xmlSecBase64Encode(samlArt, 42, 0);
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
      LASSO_PROFILE_CONTEXT(login)->msg_relayState = g_strdup(relayState);
    }
    break;
  }
  login->assertionArtifact = g_strdup(b64_samlArt);
  xmlFree(url);
  xmlFree(b64_samlArt);
  xmlFree(relayState);
  
  return (0);
}

gint
lasso_login_build_authn_request_msg(LassoLogin *login)
{
  LassoProvider *provider, *remote_provider;
  xmlChar *md_authnRequestsSigned = NULL;
  xmlChar *request_protocolProfile = NULL;
  xmlChar *url = NULL;
  xmlChar *query = NULL;
  xmlChar *lareq = NULL;
  gboolean must_sign;
  gint ret = 0;
  
  provider = LASSO_PROVIDER(LASSO_PROFILE_CONTEXT(login)->server);
  remote_provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(login)->server,
					      LASSO_PROFILE_CONTEXT(login)->remote_providerID);

  /* check if authnRequest must be signed */
  md_authnRequestsSigned = lasso_node_get_child_content(provider->metadata, "AuthnRequestsSigned", NULL);
  if (md_authnRequestsSigned != NULL) {
    must_sign = xmlStrEqual(md_authnRequestsSigned, "true");
    xmlFree(md_authnRequestsSigned);
  }
  else {
    /* FIXME : is there a default value for AuthnRequestsSigned */
    must_sign = 0;
    debug(WARNING, "The element 'AuthnRequestsSigned' is missing in metadata of server.\n");
  }

  /* export request depending on the request ProtocolProfile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(remote_provider);
  if (request_protocolProfile == NULL) {
    /* FIXME : is there a default value for SingleSignOnProtocolProfile */
    debug(WARNING, "The element 'SingleSignOnProtocolProfile' is missing in metadata of remote provider.\n");    
    ret = -1;
  }

  /* get SingleSignOnServiceURL metadata */
  if (ret == 0) {
    url = lasso_provider_get_singleSignOnServiceURL(remote_provider);
    if (url == NULL) {
      debug(ERROR, "The element 'SingleSignOnServiceURL' is missing in metadata of remote provider.\n");
      ret = -2;
    }
  }
  
  if (ret == 0) {
    if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
      /* GET -> query */
      if (must_sign) {
	query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(login)->request,
					   LASSO_PROFILE_CONTEXT(login)->server->signature_method,
					   LASSO_PROFILE_CONTEXT(login)->server->private_key);
	if (query == NULL) {
	  debug(ERROR, "Failed to create AuthnRequest query (signed).\n");
	  ret = -3;
	}
      }
      else {
	query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(login)->request, 0, NULL);
	if (query == NULL) {
	  debug(ERROR, "Failed to create AuthnRequest query.\n");
	  ret = -3;
	}
      }
      if (ret == 0) {
	/* alloc msg_url (+2 for the ? and \0) */
	LASSO_PROFILE_CONTEXT(login)->msg_url = (gchar *) g_new(gchar, strlen(url) + strlen(query) + 2);
	g_sprintf(LASSO_PROFILE_CONTEXT(login)->msg_url, "%s?%s", url, query);
	LASSO_PROFILE_CONTEXT(login)->msg_body = NULL;
	g_free(query);
      }
    }
    else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
      /* POST -> formular */
      lareq = lasso_node_export_to_base64(LASSO_PROFILE_CONTEXT(login)->request);
      if (lareq != NULL) {
	LASSO_PROFILE_CONTEXT(login)->msg_url = g_strdup(url);
	LASSO_PROFILE_CONTEXT(login)->msg_body = lareq;
      }
      else {
	debug(ERROR, "Failed to export AuthnRequest (Base64 encoded).\n");
	ret = -3;
      }
    }
  }
  xmlFree(url);
  xmlFree(request_protocolProfile);

  return (ret);
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
  if (login->protocolProfile != lassoLoginProtocolProfileBrwsPost) {
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

gint
lasso_login_create_user(LassoLogin *login,
			gchar      *user_dump)
{
  LassoNode *assertion = NULL;
  LassoNode *nameIdentifier = NULL;
  LassoNode *idpProvidedNameIdentifier = NULL;
  LassoNode *copy_idpProvidedNameIdentifier = NULL;
  LassoIdentity *identity = NULL;
  gint ret = 0;

  if (user_dump != NULL) {
    LASSO_PROFILE_CONTEXT(login)->user = lasso_user_new_from_dump(user_dump);
    if (LASSO_PROFILE_CONTEXT(login)->user == NULL) {
      debug(ERROR, "Failed to create the user from the user dump\n");
      ret = -1;
      goto done;
    }
  }
  else {
    LASSO_PROFILE_CONTEXT(login)->user = lasso_user_new();
  }

  if (LASSO_PROFILE_CONTEXT(login)->response != NULL) {
    assertion = lasso_node_get_child(LASSO_PROFILE_CONTEXT(login)->response,
				     "Assertion", lassoLibHRef);
    if (assertion == NULL) {
      debug(ERROR, "Assertion element not found in response.\n");
      ret = -2;
      goto done;
    }

    /* put response assertion in user object */
    lasso_user_add_assertion(LASSO_PROFILE_CONTEXT(login)->user,
			     LASSO_PROFILE_CONTEXT(login)->remote_providerID,
			     lasso_node_copy(assertion));

    /* put the 2 NameIdentifiers in user object */
    nameIdentifier = lasso_node_get_child(assertion, "NameIdentifier", lassoSamlAssertionHRef);
    if (nameIdentifier == NULL) {
      debug(ERROR, "NameIdentifier element not found in assertion.\n");
      ret = -3;
      goto done;
    }

    idpProvidedNameIdentifier = lasso_node_get_child(assertion, "IDPProvidedNameIdentifier", lassoLibHRef);
    if (idpProvidedNameIdentifier == NULL) {
      debug(ERROR, "IDPProvidedNameIdentifier element not found in assertion.\n");
      ret = -4;
      goto done;
    }
    copy_idpProvidedNameIdentifier = lasso_node_copy(idpProvidedNameIdentifier);
    lasso_node_destroy(idpProvidedNameIdentifier);
    /* transform the lib:IDPProvidedNameIdentifier into a saml:NameIdentifier */
    LASSO_NODE_GET_CLASS(copy_idpProvidedNameIdentifier)->set_name(copy_idpProvidedNameIdentifier, "NameIdentifier");
    LASSO_NODE_GET_CLASS(copy_idpProvidedNameIdentifier)->set_ns(copy_idpProvidedNameIdentifier,
								 lassoSamlAssertionHRef,
								 lassoSamlAssertionPrefix);

    /* create identity */
    identity = lasso_identity_new(LASSO_PROFILE_CONTEXT(login)->remote_providerID);
    lasso_identity_set_local_nameIdentifier(identity, nameIdentifier);
    lasso_identity_set_remote_nameIdentifier(identity, copy_idpProvidedNameIdentifier);
    lasso_user_add_identity(LASSO_PROFILE_CONTEXT(login)->user,
			    LASSO_PROFILE_CONTEXT(login)->remote_providerID,
			    identity);
  }
  else {
    debug(ERROR, "response attribute is empty.\n");
  }
  
 done:
  lasso_node_destroy(nameIdentifier);
  lasso_node_destroy(copy_idpProvidedNameIdentifier);
  lasso_node_destroy(assertion);

  return (ret);
}

void
lasso_login_destroy(LassoLogin *login)
{
  g_object_unref(G_OBJECT(login));
}

gchar*
lasso_login_dump(LassoLogin *login)
{
  LassoNode *node;
  gchar *parent_dump, *dump;
  gchar *protocolProfile = g_new0(gchar, 6);

  parent_dump = lasso_profile_context_dump(LASSO_PROFILE_CONTEXT(login), "LassoLogin");
  node = lasso_node_new_from_dump(parent_dump);
  g_free(parent_dump);

  sprintf(protocolProfile, "%d", login->protocolProfile);
  LASSO_NODE_GET_CLASS(node)->new_child(node, "ProtocolProfile", protocolProfile, FALSE);
  g_free(protocolProfile);

  if (login->nameIdentifier != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "NameIdentifier", login->nameIdentifier, FALSE);
  }
  if (login->assertionArtifact != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "AssertionArtifact", login->assertionArtifact, FALSE);
  }
  if (login->response_dump != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "ResponseDump", login->response_dump, FALSE);
  }

  dump = lasso_node_export(node);
  lasso_node_destroy(node);

  return (dump);
}

gint
lasso_login_init_authn_request(LassoLogin  *login,
			       const gchar *remote_providerID)
{
  g_return_val_if_fail(remote_providerID != NULL, -1);
  
  LASSO_PROFILE_CONTEXT(login)->request = lasso_authn_request_new(LASSO_PROFILE_CONTEXT(login)->server->providerID);
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeAuthnRequest;
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = g_strdup(remote_providerID);

  if (LASSO_PROFILE_CONTEXT(login)->request == NULL) {
    return (-2);
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
  gboolean  must_verify_signature, signature_status = 0;

  if (authn_request_method != lassoHttpMethodRedirect && \
      authn_request_method != lassoHttpMethodGet && \
      authn_request_method != lassoHttpMethodPost) {
    debug(ERROR, "Invalid HTTP method, it could be REDIRECT/GET or POST\n.");
    return (-1);
  }

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
    debug(ERROR, "HTTP method POST isn't implemented yet.\n");
    return (-2);
  }
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeAuthnRequest;

  /* get ProtocolProfile */
  protocolProfile = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
						 "ProtocolProfile", NULL);
  if (protocolProfile == NULL) {
    login->protocolProfile = lassoLoginProtocolProfileBrwsArt;
  }
  else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileBrwsArt)) {
    login->protocolProfile = lassoLoginProtocolProfileBrwsArt;
  }
  else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileBrwsPost)) {
    login->protocolProfile = lassoLoginProtocolProfileBrwsPost;
  }

  /* build response */
  switch (login->protocolProfile) {
  case lassoLoginProtocolProfileBrwsPost:
    /* create LibAuthnResponse */
    LASSO_PROFILE_CONTEXT(login)->response = lasso_authn_response_new(LASSO_PROFILE_CONTEXT(login)->server->providerID,
								      LASSO_PROFILE_CONTEXT(login)->request);
    LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeAuthnResponse;
    break;
  case lassoLoginProtocolProfileBrwsArt:
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
      debug(DEBUG, "Query signature has been verified\n");
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
      case 0: /* Invalid Signature */
	lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						  lassoLibStatusCodeInvalidSignature);
	break;
      case 2: /* Unsigned AuthnRequest */
	lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
						  lassoLibStatusCodeUnsignedAuthnRequest);
	break;
      }
      return (-2);
    }
  }
  return (0);
}

gint
lasso_login_init_request(LassoLogin       *login,
			 gchar            *response_msg,
			 lassoHttpMethods  response_method)
{
  LassoNode *response = NULL;
  xmlChar *artifact, *identityProviderSuccinctID;

  if (response_method != lassoHttpMethodRedirect && \
      response_method != lassoHttpMethodGet && \
      response_method != lassoHttpMethodPost) {
    debug(ERROR, "Invalid HTTP method, it could be REDIRECT/GET or POST\n.");
    return (-1);
  }

  /* rebuild response (artifact) */
  switch (response_method) {
  case lassoHttpMethodGet:
  case lassoHttpMethodRedirect:
    /* artifact by REDIRECT */
    response = lasso_artifact_new_from_query(response_msg);
    break;
  case lassoHttpMethodPost:
    /* artifact by POST */
    response = lasso_artifact_new_from_lares(response_msg, NULL);
    break;
  }
  LASSO_PROFILE_CONTEXT(login)->response = response;
  /* get remote identityProviderSuccinctID */
  identityProviderSuccinctID = lasso_artifact_get_identityProviderSuccinctID(LASSO_ARTIFACT(response));
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = lasso_server_get_providerID_from_hash(LASSO_PROFILE_CONTEXT(login)->server,
											  identityProviderSuccinctID);
  xmlFree(identityProviderSuccinctID);
  
  LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeArtifact;

  /* create SamlpRequest */
  artifact = lasso_artifact_get_samlArt(LASSO_ARTIFACT(LASSO_PROFILE_CONTEXT(login)->response));
  LASSO_PROFILE_CONTEXT(login)->request = lasso_request_new(artifact);
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeRequest;
  xmlFree(artifact);

  return (0);
}

gboolean
lasso_login_must_authenticate(LassoLogin *login)
{
  gboolean  must_authenticate = FALSE;
  gboolean  isPassive = TRUE;
  gboolean  forceAuthn = FALSE;
  gchar    *str;

  /* verify if the user must be authenticated or not */
  str = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request, "IsPassive", NULL);
  if (str != NULL) {
    if (xmlStrEqual(str, "false")) {
      isPassive = FALSE;
    }
    xmlFree(str);
  }

  str = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request, "ForceAuthn", NULL);
  if (str != NULL) {
    if (xmlStrEqual(str, "true")) {
      forceAuthn = TRUE;
    }
    xmlFree(str);
  }

  if ((forceAuthn == TRUE || LASSO_PROFILE_CONTEXT(login)->user == NULL) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (LASSO_PROFILE_CONTEXT(login)->user == NULL && isPassive == TRUE) {
    lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(login),
					      lassoLibStatusCodeNoPassive);
  }

  return (must_authenticate);
}

gint
lasso_login_process_authn_response_msg(LassoLogin *login,
				       gchar      *authn_response_msg)
{
  LASSO_PROFILE_CONTEXT(login)->response = lasso_authn_response_new_from_export(authn_response_msg,
										lassoNodeExportTypeBase64);
  LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeAuthnResponse;

  return (lasso_login_process_response_status_and_assertion(login));
}

gint
lasso_login_process_request_msg(LassoLogin *login,
				gchar      *request_msg)
{
  LASSO_PROFILE_CONTEXT(login)->request = lasso_request_new_from_export(request_msg,
									lassoNodeExportTypeSoap);
  LASSO_PROFILE_CONTEXT(login)->request_type = lassoMessageTypeRequest;

  login->assertionArtifact = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(login)->request,
							  "AssertionArtifact", lassoSamlProtocolHRef);

  return (0);
}

gint
lasso_login_process_response_msg(LassoLogin  *login,
				 gchar       *response_msg)
{
  LASSO_PROFILE_CONTEXT(login)->response = lasso_response_new_from_export(response_msg,
									  lassoNodeExportTypeSoap);
  LASSO_PROFILE_CONTEXT(login)->response_type = lassoMessageTypeResponse;

  return (lasso_login_process_response_status_and_assertion(login));
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_login_finalize(LassoLogin *login)
{  
  debug(DEBUG, "Login object 0x%x finalized ...\n", login);

  g_free(login->assertionArtifact);
  g_free(login->nameIdentifier);
  g_free(login->response_dump);

  parent_class->finalize(G_OBJECT(login));
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
}

static void
lasso_login_class_init(LassoLoginClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->finalize = (void *)lasso_login_finalize;
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

LassoLogin*
lasso_login_new(LassoServer *server,
		LassoUser   *user)
{
  LassoLogin *login;

  login = LASSO_LOGIN(g_object_new(LASSO_TYPE_LOGIN,
				   "server", server,
				   "user", user,
				   NULL));
  
  return (login);
}

LassoLogin*
lasso_login_new_from_dump(LassoServer *server,
			  LassoUser   *user,
			  gchar       *dump)
{
  LassoLogin *login;
  LassoNode *node_dump, *request_node, *response_node;
  gchar *protocolProfile;

  login = LASSO_LOGIN(g_object_new(LASSO_TYPE_LOGIN,
				   "server", server,
				   "user", user,
				   NULL));
  
  node_dump = lasso_node_new_from_dump(dump);

  /* profile context attributes */
  LASSO_PROFILE_CONTEXT(login)->remote_providerID = lasso_node_get_child_content(node_dump, "RemoteProviderID", NULL);
  LASSO_PROFILE_CONTEXT(login)->msg_url        = lasso_node_get_child_content(node_dump, "MsgUrl", NULL);
  LASSO_PROFILE_CONTEXT(login)->msg_body       = lasso_node_get_child_content(node_dump, "MsgBody", NULL);
  LASSO_PROFILE_CONTEXT(login)->msg_relayState = lasso_node_get_child_content(node_dump, "MsgRelayState", NULL);

  LASSO_PROFILE_CONTEXT(login)->request_type = atoi(lasso_node_get_child_content(node_dump, "RequestType", NULL));
  request_node = lasso_node_get_child(node_dump, "Request", NULL);
  if (request_node != NULL) {
    switch (LASSO_PROFILE_CONTEXT(login)->request_type) {
    case lassoMessageTypeAuthnRequest:
      LASSO_PROFILE_CONTEXT(login)->request = lasso_authn_request_new_from_export(lasso_node_export(request_node),
										  lassoNodeExportTypeXml);
      break;
    case lassoMessageTypeRequest:
      LASSO_PROFILE_CONTEXT(login)->request = lasso_request_new_from_export(lasso_node_export(request_node),
									    lassoNodeExportTypeXml);
      break;
    default:
      break; /* XXX */
    }
    lasso_node_destroy(request_node);
  }

  LASSO_PROFILE_CONTEXT(login)->response_type = atoi(lasso_node_get_child_content(node_dump, "ResponseType", NULL));
  response_node = lasso_node_get_child(node_dump, "Response", NULL);
  if (response_node != NULL) {
    switch (LASSO_PROFILE_CONTEXT(login)->response_type) {
    case lassoMessageTypeAuthnResponse:
      LASSO_PROFILE_CONTEXT(login)->response = lasso_authn_response_new_from_export(lasso_node_export(response_node),
										    lassoNodeExportTypeXml);
      break;
    case lassoMessageTypeRequest:
      LASSO_PROFILE_CONTEXT(login)->response = lasso_response_new_from_export(lasso_node_export(response_node),
									      lassoNodeExportTypeXml);
      break;
    default:
      break; /* XXX */
    }
    lasso_node_destroy(response_node);
  }

  LASSO_PROFILE_CONTEXT(login)->provider_type = atoi(lasso_node_get_child_content(node_dump, "ProviderType", NULL));

  /* login attributes */
  protocolProfile = lasso_node_get_child_content(node_dump, "ProtocolProfile", NULL);
  if (protocolProfile != NULL) {
    login->protocolProfile   = atoi(protocolProfile);
  }
  login->nameIdentifier    = lasso_node_get_child_content(node_dump, "NameIdentifier", NULL);
  login->assertionArtifact = lasso_node_get_child_content(node_dump, "AssertionArtifact", NULL);
  login->response_dump     = lasso_node_get_child_content(node_dump, "ResponseDump", NULL);

  lasso_node_destroy(node_dump);

  return (login);
}
