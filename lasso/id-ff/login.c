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

struct _LassoLoginPrivate
{
  gboolean dispose_has_run;
};

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

static gchar*
lasso_login_get_assertion_nameIdentifier(LassoNode  *assertion,
					 GError    **err)
{
  xmlChar *ni, *idp_ni;

  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  ni = lasso_node_get_child_content(assertion, "NameIdentifier", NULL, NULL);
  idp_ni = lasso_node_get_child_content(assertion, "IDPProvidedNameIdentifier",
					NULL, NULL);

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
      g_set_error(err, g_quark_from_string("Lasso"),
		  LASSO_XML_ERROR_UNDEFINED,
		  "NameIdentifier value not found in Assertion element.\n");
      return (NULL);
    }
  }
}

static gint
lasso_login_add_response_assertion(LassoLogin      *login,
				   LassoFederation *federation,
				   const gchar     *authenticationMethod,
				   const gchar     *reauthenticateOnOrAfter)
{
  LassoNode *assertion = NULL, *as;
  xmlChar *requestID;
  GError *err = NULL;
  gint ret = 0;

  /* get RequestID to build Assertion */
  requestID = lasso_node_get_attr_value(LASSO_NODE(LASSO_PROFILE(login)->request),
					"RequestID", &err);
  if (requestID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    return(ret);
  }
  assertion = lasso_assertion_new(LASSO_PROFILE(login)->server->providerID,
				  requestID);
  xmlFree(requestID);

  as = lasso_authentication_statement_new(authenticationMethod,
					  reauthenticateOnOrAfter,
					  LASSO_SAML_NAME_IDENTIFIER(federation->remote_nameIdentifier),
					  LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));
  if (as != NULL) {
    lasso_saml_assertion_add_authenticationStatement(LASSO_SAML_ASSERTION(assertion),
						     LASSO_SAML_AUTHENTICATION_STATEMENT(as));
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Failed to build the AuthenticationStatement element of the Assertion.\n");
    ret = -2;
    goto done;
  }

  /* store NameIdentifier */
  LASSO_PROFILE(login)->nameIdentifier = lasso_login_get_assertion_nameIdentifier(assertion, &err);
  if (LASSO_PROFILE(login)->nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* FIXME : How to know if the assertion must be signed or unsigned ? */
  ret = lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
					   LASSO_PROFILE(login)->server->signature_method,
					   LASSO_PROFILE(login)->server->private_key,
					   LASSO_PROFILE(login)->server->certificate,
					   &err);
  if (ret == 0) {
    lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response),
				       assertion);
  
    /* store assertion in session object */
    if (LASSO_PROFILE(login)->session == NULL) {
      LASSO_PROFILE(login)->session = lasso_session_new();
    }
    lasso_session_add_assertion(LASSO_PROFILE(login)->session,
				LASSO_PROFILE(login)->remote_providerID,
				assertion);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
  }

 done:
  lasso_node_destroy(as);
  lasso_node_destroy(assertion);

  return (ret);
}

static gint
lasso_login_process_federation(LassoLogin *login)
{
  LassoFederation *federation;
  LassoNode *nameIdentifier;
  xmlChar *id, *nameIDPolicy, *consent;
  gint ret = 0;
  GError *err = NULL;

  /* verify if a identity exists else create it */
  if (LASSO_PROFILE(login)->identity == NULL) {
    LASSO_PROFILE(login)->identity = lasso_identity_new();
  }
  federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
					     LASSO_PROFILE(login)->remote_providerID);
  nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
					      "NameIDPolicy", lassoLibHRef, NULL);
  if (nameIDPolicy == NULL || xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone)) {
    if (federation == NULL) {
      lasso_profile_set_response_status(LASSO_PROFILE(login),
					lassoLibStatusCodeFederationDoesNotExist);
      ret = -2;
      goto done;
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)) {
    debug("NameIDPolicy is federated\n");
    consent = lasso_node_get_attr_value(LASSO_PROFILE(login)->request,
					"consent", &err);
    if (consent != NULL) {
      if (!xmlStrEqual(consent, lassoLibConsentObtained)) {
	lasso_profile_set_response_status(LASSO_PROFILE(login),
					  lassoSamlStatusCodeRequestDenied);
	message(G_LOG_LEVEL_WARNING, "Consent not obtained");
	ret = -3;
	goto done;
      }
    }
    else {
      lasso_profile_set_response_status(LASSO_PROFILE(login),
					lassoSamlStatusCodeRequestDenied);
      message(G_LOG_LEVEL_WARNING, err->message);
      ret = err->code;
      g_error_free(err);
      goto done;
    }
    if (federation == NULL) {
      federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);

      /* set local NameIdentifier in federation */
      id = lasso_build_unique_id(32);
      nameIdentifier = lasso_saml_name_identifier_new(id);
      xmlFree(id);
      lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier),
						   LASSO_PROFILE(login)->server->providerID);
      lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier),
					    lassoLibNameIdentifierFormatFederated);
      lasso_federation_set_local_nameIdentifier(federation, nameIdentifier);
      lasso_node_destroy(nameIdentifier);

      lasso_identity_add_federation(LASSO_PROFILE(login)->identity,
				    LASSO_PROFILE(login)->remote_providerID,
				    federation);
    }
    else {
      debug("Ok, an federation was found.\n");
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    /* TODO */
  }

 done:
  lasso_federation_destroy(federation);
  xmlFree(nameIDPolicy);
  xmlFree(consent);

  return (ret);
}

static gint
lasso_login_process_response_status_and_assertion(LassoLogin *login) {
  LassoNode *assertion = NULL, *status = NULL, *statusCode = NULL;
  LassoProvider *idp = NULL;
  gchar *statusCode_value = NULL;
  gint signature_check;
  gint ret = 0;
  GError *err = NULL;

  assertion = lasso_node_get_child(LASSO_PROFILE(login)->response,
				   "Assertion",
				   lassoLibHRef,
				   &err);
  idp = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
				      LASSO_PROFILE(login)->remote_providerID);

  if (assertion != NULL) {
    /* verify signature */
    if (idp->ca_certificate != NULL) {
      signature_check = lasso_node_verify_signature(assertion, idp->ca_certificate, &err);
      if (signature_check < 0) {
	message(G_LOG_LEVEL_CRITICAL, err->message);
	ret = err->code;
	g_clear_error(&err);
	/* we continue */
      }
    }

    /* store NameIdentifier */
    LASSO_PROFILE(login)->nameIdentifier = lasso_login_get_assertion_nameIdentifier(assertion, &err);
    if (LASSO_PROFILE(login)->nameIdentifier == NULL) {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_clear_error(&err);
      /* we continue */
    }
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_clear_error(&err);
    /* we continue */
  }

  /* check StatusCode value */
  status = lasso_node_get_child(LASSO_PROFILE(login)->response,
				"Status", lassoSamlProtocolHRef, &err);
  if (status == NULL) {
    goto done;
  }
  statusCode = lasso_node_get_child(status, "StatusCode", lassoSamlProtocolHRef, &err);
  if (statusCode == NULL) {
    goto done;
  }
  statusCode_value = lasso_node_get_attr_value(statusCode, "Value", &err);
  if (statusCode_value != NULL) {
    if (!xmlStrEqual(statusCode_value, lassoSamlStatusCodeSuccess)) {
      ret = -7;
    }
  }

 done:
  if (err != NULL) {
    if (err->code < 0) {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_clear_error(&err);
    }
  }
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
lasso_login_accept_sso(LassoLogin *login)
{
  LassoNode *assertion = NULL;
  LassoNode *nameIdentifier = NULL;
  LassoNode *idpProvidedNameIdentifier = NULL;
  LassoNode *copy_idpProvidedNameIdentifier = NULL;
  LassoFederation *federation = NULL;
  gint ret = 0;

  if(LASSO_PROFILE(login)->identity == NULL) {
    LASSO_PROFILE(login)->identity = lasso_identity_new();    
  }
  if(LASSO_PROFILE(login)->session == NULL) {
    LASSO_PROFILE(login)->session = lasso_session_new();
  }

  if (LASSO_PROFILE(login)->response != NULL) {
    assertion = lasso_node_get_child(LASSO_PROFILE(login)->response,
				     "Assertion", lassoLibHRef, NULL);
    if (assertion == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Assertion element not found in response.\n");
      ret = -2;
      goto done;
    }

    /* put response assertion in identity object */
    lasso_session_add_assertion(LASSO_PROFILE(login)->session,
				LASSO_PROFILE(login)->remote_providerID,
				assertion);

    /* put the 2 NameIdentifiers in identity object */
    nameIdentifier = lasso_node_get_child(assertion, "NameIdentifier",
					  lassoSamlAssertionHRef, NULL);
    if (nameIdentifier == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "NameIdentifier element not found in assertion.\n");
      ret = -3;
      goto done;
    }

    idpProvidedNameIdentifier = lasso_node_get_child(assertion, "IDPProvidedNameIdentifier",
						     lassoLibHRef, NULL);
    if (idpProvidedNameIdentifier == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "IDPProvidedNameIdentifier element not found in assertion.\n");
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

    /* create federation */
    federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
    lasso_federation_set_local_nameIdentifier(federation, nameIdentifier);
    lasso_federation_set_remote_nameIdentifier(federation, copy_idpProvidedNameIdentifier);
    lasso_identity_add_federation(LASSO_PROFILE(login)->identity,
				  LASSO_PROFILE(login)->remote_providerID,
				  federation);
    lasso_federation_destroy(federation);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "response attribute is empty.\n");
  }
  
 done:
  lasso_node_destroy(nameIdentifier);
  lasso_node_destroy(copy_idpProvidedNameIdentifier);
  lasso_node_destroy(assertion);

  return (ret);
}

gint
lasso_login_build_artifact_msg(LassoLogin      *login,
			       gint             authentication_result,
			       const gchar     *authenticationMethod,
			       const gchar     *reauthenticateOnOrAfter,
			       lassoHttpMethod  method)
{
  LassoFederation *federation = NULL;
  LassoProvider *remote_provider;

  gchar   *b64_samlArt, *samlArt, *url;
  xmlChar *relayState;
  xmlChar *assertionHandle, *identityProviderSuccinctID;

  g_return_val_if_fail(authenticationMethod != NULL && reauthenticateOnOrAfter != NULL, -1);

  if (method != lassoHttpMethodRedirect && method != lassoHttpMethodPost) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it could be REDIRECT or POST\n.");
    return (-2);
  }

  /* ProtocolProfile must be BrwsArt */
  if (login->protocolProfile != lassoLoginProtocolProfileBrwsArt) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to build artifact message, an AuthnResponse is required by ProtocolProfile.\n");
    return (-3);
  }

  if (authentication_result == 0) {
    lasso_profile_set_response_status(LASSO_PROFILE(login),
				      lassoSamlStatusCodeRequestDenied);
  }
  else {
    /* federation */
    lasso_login_process_federation(login);
    federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
					       LASSO_PROFILE(login)->remote_providerID);
    /* fill the response with the assertion */
    if (federation != NULL) {
      lasso_login_add_response_assertion(login,
					 federation,
					 authenticationMethod,
					 reauthenticateOnOrAfter);
      lasso_federation_destroy(federation);
    }
  }
  /* save response dump */
  login->response_dump = lasso_node_export_to_soap(LASSO_PROFILE(login)->response);

  /* build artifact infos */
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID);
  /* liberty-idff-bindings-profiles-v1.2.pdf p.25 */
  url = lasso_provider_get_assertionConsumerServiceURL(remote_provider, lassoProviderTypeSp, NULL);
  samlArt = g_new(gchar, 2+20+20+1);
  identityProviderSuccinctID = lasso_str_hash(LASSO_PROFILE(login)->server->providerID,
					      LASSO_PROFILE(login)->server->private_key);
  assertionHandle = lasso_build_random_sequence(20);
  g_sprintf(samlArt, "%c%c%s%s", 0, 3, identityProviderSuccinctID, assertionHandle);
  g_free(assertionHandle);
  xmlFree(identityProviderSuccinctID);
  b64_samlArt = (gchar *)xmlSecBase64Encode(samlArt, 42, 0);
  g_free(samlArt);
  relayState = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
					    "RelayState", NULL, NULL);

  switch (method) {
  case lassoHttpMethodRedirect:
    LASSO_PROFILE(login)->msg_url = g_new(gchar, 1024+1);
    g_sprintf(LASSO_PROFILE(login)->msg_url, "%s?SAMLart=%s", url, b64_samlArt);
    if (relayState != NULL) {
      g_sprintf(LASSO_PROFILE(login)->msg_url, "%s&RelayState=%s",
	      LASSO_PROFILE(login)->msg_url, relayState);
    }
    break;
  case lassoHttpMethodPost:
    LASSO_PROFILE(login)->msg_url  = g_strdup(url);
    LASSO_PROFILE(login)->msg_body = g_strdup(b64_samlArt);
    if (relayState != NULL) {
      LASSO_PROFILE(login)->msg_relayState = g_strdup(relayState);
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
  GError *err = NULL;
  
  provider = LASSO_PROVIDER(LASSO_PROFILE(login)->server);
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID);

  /* check if authnRequest must be signed */
  md_authnRequestsSigned = lasso_provider_get_authnRequestsSigned(provider, &err);
  if (md_authnRequestsSigned != NULL) {
    must_sign = xmlStrEqual(md_authnRequestsSigned, "true");
    xmlFree(md_authnRequestsSigned);
  }
  else {
    /* AuthnRequestsSigned metadata is required in metadata */
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* export request depending on the request ProtocolProfile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(remote_provider, &err);
  if (request_protocolProfile == NULL) {
    /* SingleSignOnProtocolProfile metadata is required */
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* get SingleSignOnServiceURL metadata */
  url = lasso_provider_get_singleSignOnServiceURL(remote_provider, &err);
  if (url == NULL) {
    /* SingleSignOnServiceURL metadata is required */
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }
  
  if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
    /* GET -> query */
    if (must_sign) {
      query = lasso_node_export_to_query(LASSO_PROFILE(login)->request,
					 LASSO_PROFILE(login)->server->signature_method,
					 LASSO_PROFILE(login)->server->private_key);
      if (query == NULL) {
	message(G_LOG_LEVEL_CRITICAL, "Failed to create AuthnRequest query (signed).\n");
	ret = -4;
	goto done;
      }
    }
    else {
      query = lasso_node_export_to_query(LASSO_PROFILE(login)->request, 0, NULL);
      if (query == NULL) {
	message(G_LOG_LEVEL_CRITICAL, "Failed to create AuthnRequest query.\n");
	ret = -4;
	goto done;
      }
    }
    /* alloc msg_url (+2 for the ? and \0) */
    LASSO_PROFILE(login)->msg_url = (gchar *) g_new(gchar, strlen(url) + strlen(query) + 2);
    g_sprintf(LASSO_PROFILE(login)->msg_url, "%s?%s", url, query);
    LASSO_PROFILE(login)->msg_body = NULL;
    g_free(query);
  }
  else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
    /* POST -> formular */
    lareq = lasso_node_export_to_base64(LASSO_PROFILE(login)->request);
    if (lareq != NULL) {
      LASSO_PROFILE(login)->msg_url = g_strdup(url);
      LASSO_PROFILE(login)->msg_body = lareq;
    }
    else {
      message(G_LOG_LEVEL_CRITICAL, "Failed to export AuthnRequest (Base64 encoded).\n");
      ret = -4;
    }
  }

 done:
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
  LassoFederation *federation;

  /* ProtocolProfile must be BrwsPost */
  if (login->protocolProfile != lassoLoginProtocolProfileBrwsPost) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to build AuthnResponse message, an Artifact is required by ProtocolProfile.\n");
    return (-1);
  }
  
  if (authentication_result == 0) {
    lasso_profile_set_response_status(LASSO_PROFILE(login),
					      lassoSamlStatusCodeRequestDenied);
  }
  else {
    /* federation */
    lasso_login_process_federation(login);
    federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
					       LASSO_PROFILE(login)->remote_providerID);
    /* fill the response with the assertion */
    if (federation != NULL) {
      lasso_login_add_response_assertion(login,
					 federation,
					 authenticationMethod,
					 reauthenticateOnOrAfter);
      lasso_federation_destroy(federation);
    }
  }
  
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID);
  /* return an authnResponse (base64 encoded) */
  LASSO_PROFILE(login)->msg_body = lasso_node_export_to_base64(LASSO_PROFILE(login)->response);
  LASSO_PROFILE(login)->msg_url  = lasso_provider_get_assertionConsumerServiceURL(remote_provider,
										  lassoProviderTypeSp,
										  NULL);

  return (0);
}

gint
lasso_login_build_request_msg(LassoLogin *login)
{
  LassoProvider *remote_provider;

  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID);
  LASSO_PROFILE(login)->msg_body = lasso_node_export_to_soap(LASSO_PROFILE(login)->request);
  LASSO_PROFILE(login)->msg_url = lasso_provider_get_soapEndpoint(remote_provider,
								  lassoProviderTypeIdp, NULL);

  return (0);
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

  parent_dump = lasso_profile_dump(LASSO_PROFILE(login), "Login");
  node = lasso_node_new_from_dump(parent_dump);
  g_free(parent_dump);

  g_sprintf(protocolProfile, "%d", login->protocolProfile);
  LASSO_NODE_GET_CLASS(node)->new_child(node, "ProtocolProfile", protocolProfile, FALSE);
  g_free(protocolProfile);

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
  
  LASSO_PROFILE(login)->request = lasso_authn_request_new(LASSO_PROFILE(login)->server->providerID);
  LASSO_PROFILE(login)->request_type = lassoMessageTypeAuthnRequest;
  LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);

  if (LASSO_PROFILE(login)->request == NULL) {
    return (-2);
  }

  return (0);
}

gint
lasso_login_init_from_authn_request_msg(LassoLogin      *login,
					gchar           *authn_request_msg,
					lassoHttpMethod  authn_request_method)
{
  LassoServer *server;
  LassoProvider *remote_provider;
  gchar *protocolProfile;
  xmlChar *md_authnRequestsSigned;
  gboolean must_verify_signature = FALSE;
  gint ret = 0;
  GError *err = NULL;

  if (authn_request_method != lassoHttpMethodRedirect && \
      authn_request_method != lassoHttpMethodPost && \
      authn_request_method != lassoHttpMethodSoap) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it could be REDIRECT, POST or SOAP (LECP)\n.");
    return (-1);
  }

  server = LASSO_PROFILE(login)->server;

  /* rebuild request */
  switch (authn_request_method) {
  case lassoHttpMethodRedirect:
    /* LibAuthnRequest send by method GET */
    LASSO_PROFILE(login)->request = lasso_authn_request_new_from_export(authn_request_msg,
									lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodPost:
    /* TODO LibAuthnRequest send by method POST */
    message(G_LOG_LEVEL_MESSAGE, "HTTP method POST isn't implemented yet.\n");
    return (-2);
  case lassoHttpMethodSoap:
    /* LibAuthnRequest send by method SOAP - usefull only for LECP */
    LASSO_PROFILE(login)->request = lasso_authn_request_new_from_export(authn_request_msg,
									lassoNodeExportTypeSoap);
    break;
  }
  LASSO_PROFILE(login)->request_type = lassoMessageTypeAuthnRequest;

  /* get ProtocolProfile */
  protocolProfile = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
						 "ProtocolProfile", NULL, NULL);
  if (protocolProfile == NULL) {
    login->protocolProfile = lassoLoginProtocolProfileBrwsArt;
  }
  else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileBrwsArt)) {
    login->protocolProfile = lassoLoginProtocolProfileBrwsArt;
  }
  else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileBrwsPost)) {
    login->protocolProfile = lassoLoginProtocolProfileBrwsPost;
  }
  xmlFree(protocolProfile);

  /* build response */
  switch (login->protocolProfile) {
  case lassoLoginProtocolProfileBrwsPost:
    /* create LibAuthnResponse */
    LASSO_PROFILE(login)->response = lasso_authn_response_new(LASSO_PROFILE(login)->server->providerID,
								      LASSO_PROFILE(login)->request);
    LASSO_PROFILE(login)->response_type = lassoMessageTypeAuthnResponse;
    break;
  case lassoLoginProtocolProfileBrwsArt:
    /* create SamlpResponse */
    LASSO_PROFILE(login)->response = lasso_response_new();
    LASSO_PROFILE(login)->response_type = lassoMessageTypeResponse;
    break;
  }

  /* get remote ProviderID */
  LASSO_PROFILE(login)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
									 "ProviderID", NULL, NULL);

  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID);
  /* Is authnRequest signed ? */
  md_authnRequestsSigned = lasso_provider_get_authnRequestsSigned(remote_provider, &err);
  if (md_authnRequestsSigned != NULL) {
    must_verify_signature = xmlStrEqual(md_authnRequestsSigned, "true");
    xmlFree(md_authnRequestsSigned);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    return (ret);
  }

  /* verify request signature */
  if (must_verify_signature) {
    switch (authn_request_method) {
    case lassoHttpMethodGet:
    case lassoHttpMethodRedirect:
      debug("Query signature has been verified\n");
      ret = lasso_query_verify_signature(authn_request_msg,
					 remote_provider->public_key,
					 LASSO_PROFILE(login)->server->private_key);
      break;
    case lassoHttpMethodPost:
      ret = lasso_node_verify_signature(LASSO_PROFILE(login)->request,
					remote_provider->ca_certificate,
					NULL);
      break;
    }
    
    /* Modify StatusCode if signature is not OK */
    if (ret == LASSO_DS_ERROR_INVALID_SIGNATURE || ret == LASSO_DS_ERROR_SIGNATURE_NOTFOUND) {
      switch (ret) {
      case LASSO_DS_ERROR_INVALID_SIGNATURE:
	lasso_profile_set_response_status(LASSO_PROFILE(login),
					  lassoLibStatusCodeInvalidSignature);
	break;
      case LASSO_DS_ERROR_SIGNATURE_NOTFOUND: /* Unsigned AuthnRequest */
	lasso_profile_set_response_status(LASSO_PROFILE(login),
					  lassoLibStatusCodeUnsignedAuthnRequest);
	break;
      }
      return (-2);
    }
  }
  return (0);
}

gint
lasso_login_init_request(LassoLogin      *login,
			 gchar           *response_msg,
			 lassoHttpMethod  response_method)
{
  LassoNode *response = NULL;
  xmlChar *artifact, *b64_identityProviderSuccinctID;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), -1);
  g_return_val_if_fail(response_msg != NULL, -1);

  if (response_method != lassoHttpMethodRedirect && \
      response_method != lassoHttpMethodPost) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it could be REDIRECT or POST\n.");
    return (-1);
  }

  printf("SourceID ProviderID hash : %s\n", lasso_str_hash("http://example-idp", LASSO_PROFILE(login)->server->private_key));
  /* rebuild response (artifact) */
  switch (response_method) {
  case lassoHttpMethodRedirect:
    /* artifact by REDIRECT */
    response = lasso_artifact_new_from_query(response_msg);
    break;
  case lassoHttpMethodPost:
    /* artifact by POST */
    response = lasso_artifact_new_from_lares(response_msg, NULL);
    break;
  }
  LASSO_PROFILE(login)->response = response;
  LASSO_PROFILE(login)->response_type = lassoMessageTypeArtifact;

  /* get remote identityProviderSuccinctID */
  b64_identityProviderSuccinctID = lasso_artifact_get_b64IdentityProviderSuccinctID(LASSO_ARTIFACT(response), &err);
  if (b64_identityProviderSuccinctID != NULL) {
    LASSO_PROFILE(login)->remote_providerID = lasso_server_get_providerID_from_hash(LASSO_PROFILE(login)->server,
										    b64_identityProviderSuccinctID);
    xmlFree(b64_identityProviderSuccinctID);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_clear_error(&err);
  }
  
  /* create SamlpRequest */
  artifact = lasso_artifact_get_samlArt(LASSO_ARTIFACT(LASSO_PROFILE(login)->response), &err);
  if (artifact != NULL) {
    LASSO_PROFILE(login)->request = lasso_request_new(artifact);
    LASSO_PROFILE(login)->request_type = lassoMessageTypeRequest;
    xmlFree(artifact);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_clear_error(&err);
  }

  return (ret);
}

gboolean
lasso_login_must_authenticate(LassoLogin *login)
{
  gboolean  must_authenticate = FALSE;
  gboolean  isPassive = TRUE;
  gboolean  forceAuthn = FALSE;
  gchar    *str;

  /* verify if the user must be authenticated or not */
  str = lasso_node_get_child_content(LASSO_PROFILE(login)->request, "IsPassive",
				     NULL, NULL);
  if (str != NULL) {
    if (xmlStrEqual(str, "false")) {
      isPassive = FALSE;
    }
    xmlFree(str);
  }

  str = lasso_node_get_child_content(LASSO_PROFILE(login)->request, "ForceAuthn",
				     NULL, NULL);
  if (str != NULL) {
    if (xmlStrEqual(str, "true")) {
      forceAuthn = TRUE;
    }
    xmlFree(str);
  }

  if ((forceAuthn == TRUE || LASSO_PROFILE(login)->session == NULL) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (LASSO_PROFILE(login)->identity == NULL && isPassive == TRUE) {
    lasso_profile_set_response_status(LASSO_PROFILE(login),
				      lassoLibStatusCodeNoPassive);
  }

  return (must_authenticate);
}

gint
lasso_login_process_authn_response_msg(LassoLogin *login,
				       gchar      *authn_response_msg)
{
  LASSO_PROFILE(login)->response = lasso_authn_response_new_from_export(authn_response_msg,
									lassoNodeExportTypeBase64);
  LASSO_PROFILE(login)->response_type = lassoMessageTypeAuthnResponse;

  return (lasso_login_process_response_status_and_assertion(login));
}

gint
lasso_login_process_request_msg(LassoLogin *login,
				gchar      *request_msg)
{
  LASSO_PROFILE(login)->request = lasso_request_new_from_export(request_msg,
								lassoNodeExportTypeSoap);
  LASSO_PROFILE(login)->request_type = lassoMessageTypeRequest;

  login->assertionArtifact = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
							  "AssertionArtifact",
							  lassoSamlProtocolHRef, NULL);

  return (0);
}

gint
lasso_login_process_response_msg(LassoLogin  *login,
				 gchar       *response_msg)
{
  LASSO_PROFILE(login)->response = lasso_response_new_from_export(response_msg,
								  lassoNodeExportTypeSoap);
  LASSO_PROFILE(login)->response_type = lassoMessageTypeResponse;

  return (lasso_login_process_response_status_and_assertion(login));
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_login_dispose(LassoLogin *login)
{
  if (login->private->dispose_has_run == TRUE) {
    return;
  }
  login->private->dispose_has_run = TRUE;

  debug("Login object 0x%x disposed ...\n", login);

  /* unref reference counted objects */

  parent_class->dispose(G_OBJECT(login));
}

static void
lasso_login_finalize(LassoLogin *login)
{  
  debug("Login object 0x%x finalized ...\n", login);

  g_free(login->assertionArtifact);
  g_free(login->response_dump);

  g_free (login->private);

  parent_class->finalize(G_OBJECT(login));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_login_instance_init(GTypeInstance   *instance,
			  gpointer         g_class)
{
  LassoLogin *login = LASSO_LOGIN(instance);

  login->private = g_new (LassoLoginPrivate, 1);
  login->private->dispose_has_run = FALSE;

  login->protocolProfile = 0;
  login->assertionArtifact = NULL;
  login->response_dump     = NULL;
}

static void
lasso_login_class_init(LassoLoginClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_login_dispose;
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
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoLogin",
				       &this_info, 0);
  }
  return this_type;
}

LassoLogin*
lasso_login_new(LassoServer *server)
{
  LassoLogin *login;

  login = LASSO_LOGIN(g_object_new(LASSO_TYPE_LOGIN,
				   "server", lasso_server_copy(server),
				   NULL));
  
  return (login);
}

LassoLogin*
lasso_login_new_from_dump(LassoServer *server,
			  gchar       *dump)
{
  LassoLogin *login;
  LassoNode *node_dump, *request_node, *response_node;
  gchar *protocolProfile, *export, *type;

  login = LASSO_LOGIN(g_object_new(LASSO_TYPE_LOGIN,
				   "server", lasso_server_copy(server),
				   NULL));
  
  node_dump = lasso_node_new_from_dump(dump);

  /* profile attributes */
  LASSO_PROFILE(login)->nameIdentifier    = lasso_node_get_child_content(node_dump, "NameIdentifier",
									 lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->remote_providerID = lasso_node_get_child_content(node_dump, "RemoteProviderID",
									 lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->msg_url        = lasso_node_get_child_content(node_dump, "MsgUrl",
								      lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->msg_body       = lasso_node_get_child_content(node_dump, "MsgBody",
								      lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->msg_relayState = lasso_node_get_child_content(node_dump, "MsgRelayState",
								      lassoLassoHRef, NULL);

  type = lasso_node_get_child_content(node_dump, "RequestType", lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->request_type = atoi(type);
  xmlFree(type);

  /* rebuild request */
  if (LASSO_PROFILE(login)->request_type == lassoMessageTypeAuthnRequest) {
    request_node = lasso_node_get_child(node_dump, "AuthnRequest", lassoLibHRef, NULL);
  }
  else if (LASSO_PROFILE(login)->request_type == lassoMessageTypeRequest) {
    request_node = lasso_node_get_child(node_dump, "Request", lassoSamlProtocolHRef, NULL);
  }
  if (request_node != NULL) {
    export = lasso_node_export(request_node);
    if (LASSO_PROFILE(login)->request_type == lassoMessageTypeAuthnRequest) {
      LASSO_PROFILE(login)->request = lasso_authn_request_new_from_export(export,
									  lassoNodeExportTypeXml);
    }
    else if (LASSO_PROFILE(login)->request_type == lassoMessageTypeRequest) {
      LASSO_PROFILE(login)->request = lasso_request_new_from_export(export,
								    lassoNodeExportTypeXml);
    }
    xmlFree(export);
    lasso_node_destroy(request_node);
  }

  type = lasso_node_get_child_content(node_dump, "ResponseType", lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->response_type = atoi(type);
  xmlFree(type);

  /* rebuild response */
  if (LASSO_PROFILE(login)->response_type == lassoMessageTypeAuthnResponse) {
    response_node = lasso_node_get_child(node_dump, "AuthnResponse", lassoLibHRef, NULL);
  }
  else if (LASSO_PROFILE(login)->response_type == lassoMessageTypeResponse) {
    response_node = lasso_node_get_child(node_dump, "Response", lassoSamlProtocolHRef, NULL);
  }
  if (response_node != NULL) {
    export = lasso_node_export(response_node);
    if (LASSO_PROFILE(login)->response_type == lassoMessageTypeAuthnResponse) {
      LASSO_PROFILE(login)->response = lasso_authn_response_new_from_export(export,
									    lassoNodeExportTypeXml);
    }
    else if (LASSO_PROFILE(login)->response_type == lassoMessageTypeResponse) {
      LASSO_PROFILE(login)->response = lasso_response_new_from_export(export,
								      lassoNodeExportTypeXml);
    }
    xmlFree(export);
    lasso_node_destroy(response_node);
  }
  
  type = lasso_node_get_child_content(node_dump, "ProviderType", lassoLassoHRef, NULL);
  LASSO_PROFILE(login)->provider_type = atoi(type);
  xmlFree(type);

  /* login attributes */
  protocolProfile = lasso_node_get_child_content(node_dump, "ProtocolProfile",
						 lassoLassoHRef, NULL);
  if (protocolProfile != NULL) {
    login->protocolProfile = atoi(protocolProfile);
    xmlFree(protocolProfile);
  }
  login->assertionArtifact = lasso_node_get_child_content(node_dump, "AssertionArtifact",
							  lassoLassoHRef, NULL);
  login->response_dump     = lasso_node_get_child_content(node_dump, "ResponseDump",
							  lassoLassoHRef, NULL);

  lasso_node_destroy(node_dump);

  return (login);
}
