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

#include <lasso/protocols/artifact.h>
#include <lasso/protocols/provider.h>
#include <lasso/protocols/elements/authentication_statement.h>

#include <lasso/environs/login.h>

static GObjectClass *parent_class = NULL;

struct _LassoLoginPrivate
{
  gboolean dispose_has_run;
};

/*****************************************************************************/
/* static methods/functions                                                  */
/*****************************************************************************/

/**
 * lasso_login_build_assertion:
 * @login: a Login
 * @federation: the Federation
 * @authenticationMethod: the authentication method
 * @reauthenticateOnOrAfter: the reauthenticate on or after time
 * 
 * Builds an assertion.
 * Assertion is stored in session property. If session property is NULL, a new
 * session is build before.
 * The NameIdentifier of the assertion is stored into nameIdentifier proprerty.
 * 
 * Return value: 0 on success or a negative value otherwise.
 **/
static gint
lasso_login_build_assertion(LassoLogin      *login,
			    LassoFederation *federation,
			    const gchar     *authenticationMethod,
			    const gchar     *reauthenticateOnOrAfter)
{
  LassoNode *assertion = NULL, *nameIdentifier, *as;
  xmlChar *id, *requestID;
  GError *err = NULL;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  /* federation MAY be NULL */

  /* get RequestID to build Assertion */
  requestID = lasso_node_get_attr_value(LASSO_NODE(LASSO_PROFILE(login)->request),
					"RequestID", &err);
  if (requestID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    return ret;
  }
  assertion = lasso_assertion_new(LASSO_PROFILE(login)->server->providerID,
				  requestID);
  xmlFree(requestID);

  if (xmlStrEqual(login->nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    /* if NameIDPolicy is 'onetime', don't use a federation */
    id = lasso_build_unique_id(32);
    nameIdentifier = lasso_saml_name_identifier_new(id);
    xmlFree(id);
    lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier),
						 LASSO_PROFILE(login)->server->providerID);
    lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier),
					  lassoLibNameIdentifierFormatOneTime);
    as = lasso_authentication_statement_new(authenticationMethod,
					    reauthenticateOnOrAfter,
					    NULL,
					    LASSO_SAML_NAME_IDENTIFIER(nameIdentifier));
    LASSO_PROFILE(login)->nameIdentifier = lasso_node_get_content(nameIdentifier, NULL);
    lasso_node_destroy(nameIdentifier);
  }
  else {
    as = lasso_authentication_statement_new(authenticationMethod,
					    reauthenticateOnOrAfter,
					    LASSO_SAML_NAME_IDENTIFIER(federation->remote_nameIdentifier),
					    LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));
  }
  if (as != NULL) {
    lasso_saml_assertion_add_authenticationStatement(LASSO_SAML_ASSERTION(assertion),
						     LASSO_SAML_AUTHENTICATION_STATEMENT(as));
  }
  else {
    ret = -2;
    goto done;
  }

  /* FIXME : How to know if the assertion must be signed or unsigned ? */
  /* signature should be added at end */
  ret = lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
					   LASSO_PROFILE(login)->server->signature_method,
					   LASSO_PROFILE(login)->server->private_key,
					   LASSO_PROFILE(login)->server->certificate);

  if (ret == 0) {
    if (login->protocolProfile == lassoLoginProtocolProfileBrwsPost) {
      /* only add assertion if response is an AuthnResponse */
      lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response),
					 assertion);
    }
    /* store assertion in session object */
    if (LASSO_PROFILE(login)->session == NULL) {
      LASSO_PROFILE(login)->session = lasso_session_new();
    }
    lasso_session_add_assertion(LASSO_PROFILE(login)->session,
				LASSO_PROFILE(login)->remote_providerID,
				assertion);
  }

 done:
  lasso_node_destroy(as);
  lasso_node_destroy(assertion);

  return ret;
}

/**
 * lasso_login_must_ask_for_consent_private:
 * @login: a LassoLogin
 * 
 * Evaluates if it is necessary to ask the consent of the Principal. 
 * This method doesn't take the isPassive value into account.
 * 
 * Return value: TRUE or FALSE
 **/
static gboolean
lasso_login_must_ask_for_consent_private(LassoLogin *login)
{
  xmlChar *nameIDPolicy, *consent;
  LassoFederation *federation = NULL;
  gboolean ret;

  nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
					      "NameIDPolicy", lassoLibHRef, NULL);

  if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone) || nameIDPolicy == NULL) {
    ret = FALSE;
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    ret = FALSE;
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated) ||  \
	   xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeAny)) {
    if (LASSO_PROFILE(login)->identity != NULL) {
      federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
						 LASSO_PROFILE(login)->remote_providerID);
    }
    if (federation != NULL) {
      ret = FALSE;
    }
    else {
      consent = lasso_node_get_attr_value(LASSO_PROFILE(login)->request,
					  "consent", NULL);
      if (consent != NULL) {
	if (xmlStrEqual(consent, lassoLibConsentObtained) || \
	    xmlStrEqual(consent, lassoLibConsentObtainedPrior) || \
	    xmlStrEqual(consent, lassoLibConsentObtainedCurrentImplicit) || \
	    xmlStrEqual(consent, lassoLibConsentObtainedCurrentExplicit)) {
	  ret = FALSE;
	}
	else if (xmlStrEqual(consent, lassoLibConsentUnavailable) || \
		 xmlStrEqual(consent, lassoLibConsentInapplicable)) {
	  ret = TRUE;
	}
	else {
	  message(G_LOG_LEVEL_CRITICAL, "Unknown consent value : %s\n", consent);
	  /* we consider consent as empty if its value is unknown/invalid */
	  ret = TRUE;
	}
	xmlFree(consent);
      }
      else {
	/* no consent */
	ret = TRUE;
      }
    }
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Unknown NameIDPolicy : %s\n", nameIDPolicy);
    /* we consider NameIDPolicy as empty (none value) if its value is unknown/invalid */
    ret = TRUE;
  }

 done:
  if (federation != NULL) {
    lasso_federation_destroy(federation);
  }
  xmlFree(nameIDPolicy);

  return ret;
}

/**
 * lasso_login_process_federation:
 * @login: a LassoLogin
 * @is_consent_obtained: is user consent obtained ?
 * 
 * Return value: a positive value on success or a negative if an error occurs.
 **/
static gint
lasso_login_process_federation(LassoLogin *login,
			       gboolean    is_consent_obtained)
{
  LassoFederation *federation = NULL;
  xmlChar *nameIDPolicy;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  /* verify if identity already exists else create it */
  if (LASSO_PROFILE(login)->identity == NULL) {
    LASSO_PROFILE(login)->identity = lasso_identity_new();
  }
  /* get nameIDPolicy in lib:AuthnRequest */
  nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
					      "NameIDPolicy", lassoLibHRef, NULL);
  login->nameIDPolicy = g_strdup(nameIDPolicy);

  /* if nameIDPolicy is 'onetime' => nothing to do */
  if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
    goto done;
  }

  /* search a federation in the identity */
  federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
					     LASSO_PROFILE(login)->remote_providerID);
  
  if ((nameIDPolicy == NULL || xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone))) {
    /* a federation MUST exist */
    if (federation == NULL) {
      /*
	if protocolProfile is lassoLoginProtocolProfileBrwsPost
	set StatusCode to FederationDoesNotExist in lib:AuthnResponse
      */
      if (login->protocolProfile == lassoLoginProtocolProfileBrwsPost) {
	lasso_profile_set_response_status(LASSO_PROFILE(login),
					  lassoLibStatusCodeFederationDoesNotExist);
      }
      ret = LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
      goto done;
    }
  }
  else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated) || \
	   xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeAny)) {
    /*
      consent is necessary, it should be obtained via consent attribute
      in lib:AuthnRequest or IDP should ask the Principal
    */
    if (lasso_login_must_ask_for_consent_private(login) == TRUE && is_consent_obtained == FALSE) {
      if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeAny)) {
	/*
	  if the NameIDPolicy element is 'any' and if the policy for the
	  Principal forbids federation, then evaluation MAY proceed as if the
	  value were onetime.
	*/
	g_free(login->nameIDPolicy);
	login->nameIDPolicy = g_strdup(lassoLibNameIDPolicyTypeOneTime);
	goto done;
      }
      else {
	/*
	  if protocolProfile is lassoLoginProtocolProfileBrwsPost
	  set StatusCode to FederationDoesNotExist in lib:AuthnResponse
	*/
	/* FIXME : is it the correct value for the StatusCode */
	if (login->protocolProfile == lassoLoginProtocolProfileBrwsPost) {
	  lasso_profile_set_response_status(LASSO_PROFILE(login),
					    lassoLibStatusCodeFederationDoesNotExist);
	}
	ret = LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
	goto done;
      }
    }
    if (federation == NULL) {
      federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
      lasso_federation_build_local_nameIdentifier(federation,
						  LASSO_PROFILE(login)->server->providerID,
						  lassoLibNameIdentifierFormatFederated,
						  NULL);
      
      lasso_identity_add_federation(LASSO_PROFILE(login)->identity,
				    LASSO_PROFILE(login)->remote_providerID,
				    federation);
    }
  }
  else {
    message(G_LOG_LEVEL_CRITICAL,
	    lasso_strerror(LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY), nameIDPolicy);
    ret = LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
    goto done;
  }

 done:
  /* store the IDP name identifier if a federation exists */
  if (federation != NULL) {
    LASSO_PROFILE(login)->nameIdentifier = lasso_node_get_content(federation->local_nameIdentifier, NULL);
    lasso_federation_destroy(federation);
  }
  xmlFree(nameIDPolicy);

  return ret;
}

static gint
lasso_login_process_response_status_and_assertion(LassoLogin *login) {
  LassoNode *assertion = NULL, *status = NULL, *statusCode = NULL;
  LassoProvider *idp = NULL;
  gchar *statusCode_value = NULL;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  /* check StatusCode value */
  status = lasso_node_get_child(LASSO_PROFILE(login)->response,
				"Status", lassoSamlProtocolHRef, &err);
  if (status == NULL) {
    ret = -1;
    goto done;
  }
  statusCode = lasso_node_get_child(status, "StatusCode", lassoSamlProtocolHRef, &err);
  if (statusCode == NULL) {
    ret = -1;
    goto done;
  }
  statusCode_value = lasso_node_get_attr_value(statusCode, "Value", &err);
  if (statusCode_value != NULL) {
    if (!xmlStrEqual(statusCode_value, lassoSamlStatusCodeSuccess)) {
      ret = -7;
      goto done;
    }
  }

  /* check assertion */
  assertion = lasso_node_get_child(LASSO_PROFILE(login)->response,
				   "Assertion",
				   NULL, /* lassoLibHRef, FIXME changed for SourceID */
				   NULL);

  if (assertion != NULL) {
    idp = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
					LASSO_PROFILE(login)->remote_providerID,
					&err);
    /* verify signature */
    if (idp != NULL) {
      /* FIXME detect X509Data ? */
      ret = lasso_node_verify_signature(assertion, idp->public_key, idp->ca_cert_chain);
      if (ret < 0) {
	goto done;
      }
    }
    else {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_error_free(err);
      goto done;
    }

    /* store NameIdentifier */
    LASSO_PROFILE(login)->nameIdentifier = lasso_node_get_child_content(assertion, "NameIdentifier",
									NULL, &err);
    if (LASSO_PROFILE(login)->nameIdentifier == NULL) {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_clear_error(&err);
      /* we continue */
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

  return ret;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_login_accept_sso:
 * @login: a LassoLogin
 * 
 * Gets the assertion of the response and adds it into the session.
 * Builds a federation with the 2 name identifiers of the assertion
 * and adds it into the identity.
 * If the session or the identity are NULL, they are created.
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_accept_sso(LassoLogin *login)
{
  LassoNode *assertion = NULL;
  LassoNode *ni = NULL;
  LassoNode *idp_ni, *idp_ni_copy = NULL;
  LassoFederation *federation = NULL;
  xmlChar *nameIdentifier_format;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  if(LASSO_PROFILE(login)->identity == NULL) {
    LASSO_PROFILE(login)->identity = lasso_identity_new();    
  }
  if(LASSO_PROFILE(login)->session == NULL) {
    LASSO_PROFILE(login)->session = lasso_session_new();
  }

  if (LASSO_PROFILE(login)->response != NULL) {
    assertion = lasso_node_get_child(LASSO_PROFILE(login)->response,
    				     "Assertion",
				     NULL, /* lassoLibHRef, FIXME changed for SourceID */
				     &err);
    if (assertion == NULL) {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_error_free(err);
      goto done;
    }

    /* put response assertion in session object */
    lasso_session_add_assertion(LASSO_PROFILE(login)->session,
				LASSO_PROFILE(login)->remote_providerID,
				assertion);

    /* get the 2 NameIdentifiers and put them in identity object */
    ni = lasso_node_get_child(assertion, "NameIdentifier",
			      lassoSamlAssertionHRef, &err);
    /* 1 - the saml:NameIdentifier SHOULD exists */
    if (ni == NULL) {
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_error_free(err);
      goto done;
    }
    /* get the format of the nameIdentifier */
    nameIdentifier_format = lasso_node_get_attr_value(LASSO_NODE(ni), "Format", NULL);
    /* FIXME : check nameIdentifier_format */

    /* 2 - the lib:IDPProvidedNameIdentifier */
    idp_ni = lasso_node_get_child(assertion, "IDPProvidedNameIdentifier",
				  lassoLibHRef, &err);
    if (idp_ni != NULL) {
      idp_ni_copy = lasso_node_copy(idp_ni);
      lasso_node_destroy(idp_ni);
      /* transform the lib:IDPProvidedNameIdentifier into a saml:NameIdentifier */
      LASSO_NODE_GET_CLASS(idp_ni_copy)->set_name(idp_ni_copy, "NameIdentifier");
      LASSO_NODE_GET_CLASS(idp_ni_copy)->set_ns(idp_ni_copy,
						lassoSamlAssertionHRef,
						lassoSamlAssertionPrefix);
    }

    /* create federation, only if nameidentifier format is Federated */
    if (xmlStrEqual(nameIdentifier_format, lassoLibNameIdentifierFormatFederated)) {
      federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
      if (ni != NULL && idp_ni_copy != NULL) {
	lasso_federation_set_local_nameIdentifier(federation, ni);
	lasso_federation_set_remote_nameIdentifier(federation, idp_ni_copy);
      }
      else {
	lasso_federation_set_remote_nameIdentifier(federation, ni);
      }
      /* add federation in identity */
      lasso_identity_add_federation(LASSO_PROFILE(login)->identity,
				    LASSO_PROFILE(login)->remote_providerID,
				    federation);
      lasso_federation_destroy(federation);
    }
    xmlFree(nameIdentifier_format);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "response attribute is empty.\n");
  }
  
 done:
  lasso_node_destroy(ni);
  lasso_node_destroy(idp_ni_copy);
  lasso_node_destroy(assertion);

  return ret;
}

/**
 * lasso_login_build_artifact_msg:
 * @login: a LassoLogin
 * @authentication_result: the authentication result
 * @authenticationMethod: the authentication method
 * @reauthenticateOnOrAfter: the time at, or after which the service provider
 * reauthenticates the Principal with the identity provider 
 * @http_method: the HTTP method to send the artifact (REDIRECT or POST)
 * 
 * Builds an artifact. Depending of the HTTP method, the data for the sending of
 * the artifact are stored in msg_url (REDIRECT) or msg_url, msg_body and
 * msg_relayState (POST).
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_build_artifact_msg(LassoLogin      *login,
			       gboolean         authentication_result,
			       gboolean         is_consent_obtained,
			       const gchar     *authenticationMethod,
			       const gchar     *reauthenticateOnOrAfter,
			       lassoHttpMethod  http_method)
{
  LassoFederation *federation = NULL;
  LassoProvider *remote_provider;
  gchar *url;
  xmlSecByte samlArt[42], *b64_samlArt, *relayState;
  xmlChar *assertionHandle, *identityProviderSuccinctID;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(authenticationMethod != NULL && reauthenticateOnOrAfter != NULL,
		       LASSO_PARAM_ERROR_INVALID_VALUE);

  if (http_method != lassoHttpMethodRedirect && http_method != lassoHttpMethodPost) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it could be REDIRECT or POST\n.");
    return LASSO_PARAM_ERROR_INVALID_VALUE;
  }

  /* ProtocolProfile must be BrwsArt */
  if (login->protocolProfile != lassoLoginProtocolProfileBrwsArt) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid ProtocolProfile : %s\n", login->protocolProfile);
    return -1;
  }
 
 /* process federation and build assertion only if signature is OK */
  if (LASSO_PROFILE(login)->signature_status == 0 && authentication_result == TRUE) {
    ret = lasso_login_process_federation(login, is_consent_obtained);
    /* fill the response with the assertion */
    if (ret == 0) {
      federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
						 LASSO_PROFILE(login)->remote_providerID);
      lasso_login_build_assertion(login,
				  federation,
				  authenticationMethod,
				  reauthenticateOnOrAfter);
      lasso_federation_destroy(federation);
    }
    else if (ret < 0) {
      return ret;
    }
  }

  /* build artifact infos */
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID,
						  NULL);
  /* liberty-idff-bindings-profiles-v1.2.pdf p.25 */
  url = lasso_provider_get_assertionConsumerServiceURL(remote_provider, lassoProviderTypeSp, NULL);
  identityProviderSuccinctID = lasso_sha1(LASSO_PROFILE(login)->server->providerID);
  assertionHandle = lasso_build_random_sequence(20);

  memcpy(samlArt, "\000\003", 2); /* byte code */
  memcpy(samlArt+2, identityProviderSuccinctID, 20);
  memcpy(samlArt+22, assertionHandle, 20);

  xmlFree(assertionHandle);
  xmlFree(identityProviderSuccinctID);
  b64_samlArt = xmlSecBase64Encode(samlArt, 42, 0);
  relayState = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
					    "RelayState", NULL, NULL);

  switch (http_method) {
  case lassoHttpMethodRedirect:
    if (relayState == NULL) {
      LASSO_PROFILE(login)->msg_url = g_strdup_printf("%s?SAMLart=%s", url, b64_samlArt);
    }
    else {
      LASSO_PROFILE(login)->msg_url = g_strdup_printf("%s?SAMLart=%s&RelayState=%s",
						      url, b64_samlArt, relayState);
    }
    break;
  case lassoHttpMethodPost:
    LASSO_PROFILE(login)->msg_url  = g_strdup(url);
    LASSO_PROFILE(login)->msg_body = g_strdup(b64_samlArt);
    if (relayState != NULL) {
      LASSO_PROFILE(login)->msg_relayState = g_strdup(relayState);
    }
    break;
  default:
    break;
  }
  LASSO_PROFILE(login)->response_type = lassoMessageTypeArtifact;
  login->assertionArtifact = g_strdup(b64_samlArt);
  xmlFree(url);
  xmlFree(b64_samlArt);
  xmlFree(relayState);
  
  return ret;
}

/**
 * lasso_login_build_authn_request_msg:
 * @login: a LassoLogin
 * @remote_providerID: the providerID of the identity provider or NULL
 * 
 * Builds an authentication request. Depending of the selected HTTP method,
 * the data for the sending of the request are stored in msg_url (GET) or
 * msg_url and msg_body (POST).
 * 
 * If remote_providerID is NULL, the providerID of the first provider
 * of server is used.
 *
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_build_authn_request_msg(LassoLogin  *login,
				    const gchar *remote_providerID)
{
  LassoProvider *provider, *remote_provider;
  xmlChar *md_authnRequestsSigned = NULL;
  xmlChar *request_protocolProfile = NULL;
  xmlChar *url = NULL;
  gchar *query = NULL;
  gchar *lareq = NULL;
  gboolean must_sign;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  if (remote_providerID != NULL) {
    LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);
  }
  else {
    LASSO_PROFILE(login)->remote_providerID = lasso_server_get_first_providerID(LASSO_PROFILE(login)->server);
  }

  provider = LASSO_PROVIDER(LASSO_PROFILE(login)->server);
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID,
						  &err);
  if (remote_provider == NULL) {
    ret = err->code;
    g_error_free(err);
    return ret;
  }

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

  /* get SingleSignOnServiceURL metadata */
  url = lasso_provider_get_singleSignOnServiceURL(remote_provider, &err);
  if (url == NULL) {
    /* SingleSignOnServiceURL metadata is required */
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }
  
  if (login->http_method == lassoHttpMethodRedirect) {
    /* REDIRECT -> query */
    if (must_sign) {
      query = lasso_node_export_to_query(LASSO_PROFILE(login)->request,
					 LASSO_PROFILE(login)->server->signature_method,
					 LASSO_PROFILE(login)->server->private_key);
      if (query == NULL) {
	message(G_LOG_LEVEL_CRITICAL, "Failed to create AuthnRequest query (signed).\n");
	ret = -3;
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
    LASSO_PROFILE(login)->msg_url = g_strdup_printf("%s?%s", url, query);
    LASSO_PROFILE(login)->msg_body = NULL;
    g_free(query);
  }
  else if (login->http_method == lassoHttpMethodPost) {
    /* POST -> formular */
    if (must_sign) {
      ret = lasso_samlp_request_abstract_sign_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(LASSO_PROFILE(login)->request),
							     LASSO_PROFILE(login)->server->private_key,
							     LASSO_PROFILE(login)->server->certificate);
    }
    if (ret < 0) {
      goto done;
    }
    lareq = lasso_node_export_to_base64(LASSO_PROFILE(login)->request);
    if (lareq != NULL) {
      LASSO_PROFILE(login)->msg_url = g_strdup(url);
      LASSO_PROFILE(login)->msg_body = lareq;
    }
    else {
      message(G_LOG_LEVEL_CRITICAL, "Failed to export AuthnRequest (Base64 encoded).\n");
      ret = -5;
    }
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid SingleSignOnProtocolProfile.\n");
  }

 done:
  xmlFree(url);
  xmlFree(request_protocolProfile);

  return ret;
}

/**
 * lasso_login_build_authn_response_msg:
 * @login: a LassoLogin
 * @authentication_result: the authentication result
 * @authenticationMethod: the authentication method
 * @reauthenticateOnOrAfter: the time at, or after which the service provider
 * reauthenticates the Principal with the identity provider 
 * 
 * Builds an authentication response. The data for the sending of the response
 * are stored in msg_url and msg_body.
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_build_authn_response_msg(LassoLogin  *login,
				     gboolean     authentication_result,
				     gboolean     is_consent_obtained,
				     const gchar *authenticationMethod,
				     const gchar *reauthenticateOnOrAfter)
{
  LassoProvider *remote_provider;
  LassoFederation *federation;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  /* ProtocolProfile must be BrwsPost */
  if (login->protocolProfile != lassoLoginProtocolProfileBrwsPost) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to build AuthnResponse message, an Artifact is required by ProtocolProfile.\n");
    return -1;
  }

  /* create LibAuthnResponse */
  LASSO_PROFILE(login)->response = lasso_authn_response_new(LASSO_PROFILE(login)->server->providerID,
							    LASSO_PROFILE(login)->request);
  LASSO_PROFILE(login)->response_type = lassoMessageTypeAuthnResponse;

  /* if signature is not OK => modify AuthnResponse StatusCode */
  if (LASSO_PROFILE(login)->signature_status == LASSO_DS_ERROR_INVALID_SIGNATURE ||
      LASSO_PROFILE(login)->signature_status == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
    switch (LASSO_PROFILE(login)->signature_status) {
    case LASSO_DS_ERROR_INVALID_SIGNATURE:
      lasso_profile_set_response_status(LASSO_PROFILE(login),
					lassoLibStatusCodeInvalidSignature);
      break;
    case LASSO_DS_ERROR_SIGNATURE_NOT_FOUND: /* Unsigned AuthnRequest */
      lasso_profile_set_response_status(LASSO_PROFILE(login),
					lassoLibStatusCodeUnsignedAuthnRequest);
      break;
    }
    /* ret = LASSO_PROFILE(login)->signature_status; */
  }
  else {
    /* modify AuthnResponse StatusCode if user authentication is not OK */
    if (authentication_result == FALSE) {
      lasso_profile_set_response_status(LASSO_PROFILE(login),
					lassoSamlStatusCodeRequestDenied);
    }

    if (LASSO_PROFILE(login)->signature_status == 0 && authentication_result == TRUE) {
      /* process federation */
      ret = lasso_login_process_federation(login, is_consent_obtained);
      /* fill the response with the assertion */
      if (ret == 0) {
	federation = lasso_identity_get_federation(LASSO_PROFILE(login)->identity,
						   LASSO_PROFILE(login)->remote_providerID);
	lasso_login_build_assertion(login,
				    federation,
				    authenticationMethod,
				    reauthenticateOnOrAfter);
	lasso_federation_destroy(federation);
      }
      else if (ret < 0) {
	return ret;
      }
    }
  }
  
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID,
						  NULL);
  /* build an lib:AuthnResponse base64 encoded */
  LASSO_PROFILE(login)->msg_body = lasso_node_export_to_base64(LASSO_PROFILE(login)->response);
  LASSO_PROFILE(login)->msg_url  = lasso_provider_get_assertionConsumerServiceURL(remote_provider,
										  lassoProviderTypeSp,
										  NULL);

  return ret;
}

/**
 * lasso_login_build_request_msg:
 * @login: a LassoLogin
 * 
 * Builds a SOAP request message. The data for the sending of the request
 * are stored in msg_url and msg_body.
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_build_request_msg(LassoLogin *login)
{
  LassoProvider *remote_provider;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  /* sign request */
  ret= lasso_samlp_request_abstract_sign_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(LASSO_PROFILE(login)->request),
							LASSO_PROFILE(login)->server->private_key,
							LASSO_PROFILE(login)->server->certificate);
  LASSO_PROFILE(login)->msg_body = lasso_node_export_to_soap(LASSO_PROFILE(login)->request);

  /* get msg_url (SOAP Endpoint) */
  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID,
						  &err);
  if (err != NULL) {
    goto done;
  }
  LASSO_PROFILE(login)->msg_url = lasso_provider_get_soapEndpoint(remote_provider,
								  lassoProviderTypeIdp, &err);
  if (err != NULL) {
    goto done;
  }
  return 0;

 done:
  message(G_LOG_LEVEL_CRITICAL, err->message);
  ret = err->code;
  g_error_free(err);
  return ret;
}

/**
 * lasso_login_build_response_msg:
 * @login: a LassoLogin
 * 
 * Builds a SOAP response message. The data for the sending of the response
 * are stored in msg_body.
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/gint
lasso_login_build_response_msg(LassoLogin *login,
			       gchar      *remote_providerID)
{
  LassoProvider *remote_provider;
  LassoNode *assertion;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), -1);

  LASSO_PROFILE(login)->response = lasso_response_new();

  if (remote_providerID != NULL) {
    LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);
    remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						    LASSO_PROFILE(login)->remote_providerID,
						    NULL);
    /* FIXME verify the SOAP request signature */
    ret = lasso_node_verify_signature(LASSO_PROFILE(login)->request,
				      remote_provider->public_key,
				      remote_provider->ca_cert_chain);
    /* changed status code into RequestDenied
       if signature is invalid or not found
       if an error occurs during verification */
    if (ret != 0) {
      lasso_profile_set_response_status(LASSO_PROFILE(login),
					lassoSamlStatusCodeRequestDenied);
    }
    
    if (LASSO_PROFILE(login)->session) {
      /* get assertion in session and add it in response */
      assertion = lasso_session_get_assertion(LASSO_PROFILE(login)->session,
					      LASSO_PROFILE(login)->remote_providerID);
      if (assertion != NULL) {
	lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response),
					   assertion);
	lasso_node_destroy(assertion);
      }
      else {
	/* FIXME should this message output by lasso_session_get_assertion () ? */
	message(G_LOG_LEVEL_CRITICAL, "Assertion not found in session\n");
      }
    }
  }
  else {
    lasso_profile_set_response_status(LASSO_PROFILE(login),
				      lassoSamlStatusCodeRequestDenied);
  }

  LASSO_PROFILE(login)->msg_body = lasso_node_export_to_soap(LASSO_PROFILE(login)->response);

  return ret;
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
  gchar protocolProfile[6], http_method[6];

  g_return_val_if_fail(LASSO_IS_LOGIN(login), NULL);

  parent_dump = lasso_profile_dump(LASSO_PROFILE(login), "Login");
  node = lasso_node_new_from_dump(parent_dump);
  g_free(parent_dump);

  g_snprintf(protocolProfile, 6, "%d", login->protocolProfile);
  LASSO_NODE_GET_CLASS(node)->new_child(node, "ProtocolProfile", protocolProfile, FALSE);

  if (login->assertionArtifact != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "AssertionArtifact", login->assertionArtifact, FALSE);
  }

  dump = lasso_node_export(node);
  lasso_node_destroy(node);

  return dump;
}

gint
lasso_login_init_authn_request(LassoLogin      *login,
			       lassoHttpMethod  http_method)
{
  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  if (http_method != lassoHttpMethodRedirect && http_method != lassoHttpMethodPost) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it must be REDIRECT or POST\n.");
    return LASSO_PARAM_ERROR_INVALID_VALUE;
  }

  login->http_method = http_method;

  if (http_method == lassoHttpMethodPost) {
    LASSO_PROFILE(login)->request = lasso_authn_request_new(LASSO_PROFILE(login)->server->providerID,
							    lassoSignatureTypeWithX509,
							    lassoSignatureMethodRsaSha1);
  }
  else {
    LASSO_PROFILE(login)->request = lasso_authn_request_new(LASSO_PROFILE(login)->server->providerID,
							    lassoSignatureTypeNone,
							    0);    
  }

  if (LASSO_PROFILE(login)->request == NULL) {
    return -2;
  }

  LASSO_PROFILE(login)->request_type = lassoMessageTypeAuthnRequest;

  return 0;
}

gint
lasso_login_init_request(LassoLogin      *login,
			 gchar           *response_msg,
			 lassoHttpMethod  response_http_method)
{
  LassoNode *response = NULL;
  xmlChar *artifact, *b64_identityProviderSuccinctID;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  if (response_http_method != lassoHttpMethodRedirect && \
      response_http_method != lassoHttpMethodPost) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it could be REDIRECT or POST\n.");
    return -1;
  }

  /* rebuild response (artifact) */
  switch (response_http_method) {
  case lassoHttpMethodRedirect:
    /* artifact by REDIRECT */
    response = lasso_artifact_new_from_query(response_msg);
    break;
  case lassoHttpMethodPost:
    /* artifact by POST */
    response = lasso_artifact_new_from_lares(response_msg, NULL);
    break;
  default:
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

  return ret;
}

/**
 * lasso_login_must_ask_for_consent:
 * @login: a LassoLogin
 * 
 * Evaluates if a consent must be ask to the Principal to federate him.
 * 
 * Return value: TRUE or FALSE
 **/
gboolean
lasso_login_must_ask_for_consent(LassoLogin *login)
{
  xmlChar *content;
  gboolean isPassive = TRUE; /* default value */
  gboolean ret = lasso_login_must_ask_for_consent_private(login);
 
  /* if must_ask_for_consent = TRUE we must return FALSE if isPassive is TRUE */
  if (ret == TRUE) {
    content = lasso_node_get_child_content(LASSO_PROFILE(login)->request, "IsPassive",
					   NULL, NULL);
    if (content != NULL) {
      if (xmlStrEqual(content, "false") || xmlStrEqual(content, "0")) {
	isPassive = FALSE;
      }
      xmlFree(content);
    }
    if (isPassive == TRUE) {
      ret = FALSE;
    }
  }

  return ret;
}

/**
 * lasso_login_must_authenticate:
 * @login: a LassoLogin
 * 
 * Verifies if the user must be authenticated or not.
 * 
 * Return value: TRUE or FALSE
 **/
gboolean
lasso_login_must_authenticate(LassoLogin *login)
{
  gboolean  must_authenticate = FALSE;
  gboolean  isPassive = TRUE;
  gboolean  forceAuthn = FALSE;
  gchar    *str;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  /* verify if the user must be authenticated or not */

  /* get IsPassive and ForceAuthn in AuthnRequest if exists */
  if (LASSO_PROFILE(login)->request != NULL) {
    str = lasso_node_get_child_content(LASSO_PROFILE(login)->request, "IsPassive",
				       NULL, NULL);
    if (str != NULL) {
      if (xmlStrEqual(str, "false") || xmlStrEqual(str, "0")) {
	isPassive = FALSE;
      }
      xmlFree(str);
    }
    
    str = lasso_node_get_child_content(LASSO_PROFILE(login)->request, "ForceAuthn",
				       NULL, NULL);
    if (str != NULL) {
      if (xmlStrEqual(str, "true") || xmlStrEqual(str, "1")) {
	forceAuthn = TRUE;
      }
      xmlFree(str);
    }
  }

  if ((forceAuthn == TRUE || LASSO_PROFILE(login)->session == NULL) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (LASSO_PROFILE(login)->identity == NULL && \
	   isPassive == TRUE && \
	   login->protocolProfile == lassoLoginProtocolProfileBrwsPost) {
    lasso_profile_set_response_status(LASSO_PROFILE(login),
				      lassoLibStatusCodeNoPassive);
  }

  return must_authenticate;
}

gint
lasso_login_process_authn_request_msg(LassoLogin      *login,
				      gchar           *authn_request_msg,
				      lassoHttpMethod  authn_request_http_method)
{
  LassoProvider *remote_provider;
  gchar *protocolProfile;
  xmlChar *md_authnRequestsSigned;
  gboolean must_verify_signature = FALSE;
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(authn_request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  if (authn_request_http_method != lassoHttpMethodRedirect && \
      authn_request_http_method != lassoHttpMethodPost && \
      authn_request_http_method != lassoHttpMethodSoap) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP method, it could be REDIRECT, POST or SOAP (LECP)\n.");
    return LASSO_PARAM_ERROR_INVALID_VALUE;
  }

  /* rebuild request */
  switch (authn_request_http_method) {
  case lassoHttpMethodRedirect:
    /* LibAuthnRequest send by method GET */
    LASSO_PROFILE(login)->request = lasso_authn_request_new_from_export(authn_request_msg,
									lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodPost:
    /* LibAuthnRequest send by method POST */
    LASSO_PROFILE(login)->request = lasso_authn_request_new_from_export(authn_request_msg,
									lassoNodeExportTypeBase64);
    break;
  case lassoHttpMethodSoap:
    /* LibAuthnRequest send by method SOAP - useful only for LECP */
    LASSO_PROFILE(login)->request = lasso_authn_request_new_from_export(authn_request_msg,
									lassoNodeExportTypeSoap);
    break;
  default:
    break;
  }
  if (LASSO_PROFILE(login)->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Message isn't an AuthnRequest\n");
    return -1;
  }

  LASSO_PROFILE(login)->request_type = lassoMessageTypeAuthnRequest;

  /* get ProtocolProfile in lib:AuthnRequest */
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
  else {
    message(G_LOG_LEVEL_CRITICAL, "Unknown protocol profile : %s\n", protocolProfile);
    xmlFree(protocolProfile);
    return -2;
  }
  xmlFree(protocolProfile);

  /* get remote ProviderID */
  LASSO_PROFILE(login)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
									 "ProviderID", NULL, NULL);

  remote_provider = lasso_server_get_provider_ref(LASSO_PROFILE(login)->server,
						  LASSO_PROFILE(login)->remote_providerID,
						  &err);
  if (remote_provider != NULL) {
    /* Is authnRequest signed ? */
    md_authnRequestsSigned = lasso_provider_get_authnRequestsSigned(remote_provider, &err);
    if (md_authnRequestsSigned != NULL) {
      must_verify_signature = xmlStrEqual(md_authnRequestsSigned, "true");
      xmlFree(md_authnRequestsSigned);
    }
    else {
      /* AuthnRequestsSigned element is required */
      message(G_LOG_LEVEL_CRITICAL, err->message);
      ret = err->code;
      g_error_free(err);
      return ret;
    }
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    return ret;
  }

  /* verify request signature */
  if (must_verify_signature) {
    switch (authn_request_http_method) {
    case lassoHttpMethodRedirect:
      ret = lasso_query_verify_signature(authn_request_msg,
					 remote_provider->public_key,
					 LASSO_PROFILE(login)->server->private_key);
      break;
    case lassoHttpMethodPost:
    case lassoHttpMethodSoap:
      /* FIXME detect X509Data ? */
      ret = lasso_node_verify_signature(LASSO_PROFILE(login)->request,
					remote_provider->public_key,
					remote_provider->ca_cert_chain);
      break;
    }
    LASSO_PROFILE(login)->signature_status = ret;
  }

  return ret;
}

gint
lasso_login_process_authn_response_msg(LassoLogin *login,
				       gchar      *authn_response_msg)
{
  gint ret1 = 0, ret2 = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(authn_response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  LASSO_PROFILE(login)->response = lasso_authn_response_new_from_export(authn_response_msg,
									lassoNodeExportTypeBase64);
  LASSO_PROFILE(login)->response_type = lassoMessageTypeAuthnResponse;

  LASSO_PROFILE(login)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE(login)->response,
									 "ProviderID",
									 lassoLibHRef,
									 &err);
  if (LASSO_PROFILE(login)->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret1 = err->code;
    g_error_free(err);
  }

  LASSO_PROFILE(login)->msg_relayState = lasso_node_get_child_content(LASSO_PROFILE(login)->response,
								      "RelayState",
								      lassoLibHRef,
								      NULL);

  ret2 = lasso_login_process_response_status_and_assertion(login);

  return ret2 == 0 ? ret1 : ret2;
}

gint
lasso_login_process_request_msg(LassoLogin *login,
				gchar      *request_msg)
{
  gint ret = 0;
  GError *err = NULL;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  /* rebuild samlp:Request with request_msg */
  LASSO_PROFILE(login)->request = lasso_request_new_from_export(request_msg,
								lassoNodeExportTypeSoap);
  if (LASSO_PROFILE(login)->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to rebuild samlp:Request with request message.\n");
    return LASSO_ERROR_UNDEFINED;
  }
  LASSO_PROFILE(login)->request_type = lassoMessageTypeRequest;

  /* get AssertionArtifact */
  login->assertionArtifact = lasso_node_get_child_content(LASSO_PROFILE(login)->request,
							  "AssertionArtifact",
							  lassoSamlProtocolHRef, &err);
  if (err != NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
  }

  return ret;
}

gint
lasso_login_process_response_msg(LassoLogin  *login,
				 gchar       *response_msg)
{
  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  /* rebuild samlp:Response with response_msg */
  LASSO_PROFILE(login)->response = lasso_response_new_from_export(response_msg,
								  lassoNodeExportTypeSoap);
  if (LASSO_PROFILE(login)->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to rebuild samlp:Response with response message.\n");
    return LASSO_ERROR_UNDEFINED;
  }
  LASSO_PROFILE(login)->response_type = lassoMessageTypeResponse;

  return lasso_login_process_response_status_and_assertion(login);
}

gint
lasso_login_process_without_authn_request_msg(LassoLogin  *login,
					      const gchar *remote_providerID,
					      const gchar *relayState)
{
  LassoNode *request;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  g_return_val_if_fail(remote_providerID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
  /* relayState can be NULL */

  /* build a fake/dummy lib:AuthnRequest */
  request = lasso_authn_request_new(remote_providerID, lassoSignatureTypeNone, 0);

  lasso_lib_authn_request_set_consent(LASSO_LIB_AUTHN_REQUEST(request),
				      lassoLibConsentObtained);
  lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(request),
					   lassoLibNameIDPolicyTypeAny);
  lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(request),
					      lassoLibProtocolProfileBrwsArt);
  if (relayState != NULL) {
    lasso_lib_authn_request_set_relayState(LASSO_LIB_AUTHN_REQUEST(request),
					   relayState);
  }
  LASSO_PROFILE(login)->request = request;

  LASSO_PROFILE(login)->request_type = lassoMessageTypeAuthnRequest;
  LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);
  login->protocolProfile = lassoLoginProtocolProfileBrwsArt;

  return ret;
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

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  login = LASSO_LOGIN(g_object_new(LASSO_TYPE_LOGIN,
				   "server", lasso_server_copy(server),
				   NULL));
  
  return login;
}

LassoLogin*
lasso_login_new_from_dump(LassoServer *server,
			  gchar       *dump)
{
  LassoLogin *login;
  LassoNode *node_dump, *request_node = NULL, *response_node = NULL;
  gchar *protocolProfile, *export, *type;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(dump != NULL, NULL);

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
    g_free(export);
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
    g_free(export);
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

  lasso_node_destroy(node_dump);

  return login;
}
