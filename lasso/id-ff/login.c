/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 * Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <string.h>
#include <glib/gprintf.h>
#include <xmlsec/base64.h>

#include <lasso/xml/errors.h>

#include <lasso/environs/login.h>
#include <lasso/environs/provider.h>

struct _LassoLoginPrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* static methods/functions */
/*****************************************************************************/

/**
 * lasso_login_build_assertion:
 * @login: a Login
 * @federation: a federation or NULL
 * @authenticationMethod: the authentication method.
 * @authenticationInstant: the time at which the authentication took place or NULL.
 * @reauthenticateOnOrAfter: the time at, or after which the service provider
 * reauthenticates the Principal with the identity provider or NULL.
 * @notBefore: the earliest time instant at which the assertion is valid or NULL.
 * @notOnOrAfter: the time instant at which the assertion has expired or NULL.
 * 
 * Builds an assertion.
 * Assertion is stored in session property. If session property is NULL, a new
 * session is build before.
 * The NameIdentifier of the assertion is stored into nameIdentifier proprerty.
 * If @authenticationInstant is NULL, the current time will be set.
 * Time values must be encoded in UTC.
 *
 * Return value: 0 on success or a negative value otherwise.
 **/
static gint
lasso_login_build_assertion(LassoLogin *login,
		LassoFederation *federation,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter)
{
	LassoLibAssertion *assertion;
	LassoLibAuthenticationStatement *as;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoProfile *profile;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	/* federation MAY be NULL */

	profile = LASSO_PROFILE(login);
	
	/*
	 get RequestID to build Assertion
	 it may be NULL when the Identity provider initiates SSO.
	 in this case, no InResponseTo will be added in assertion
	 (XXX: what does that mean ?  would profile->request also be NULL?)
	 */
	assertion = lasso_lib_assertion_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->RequestID,
			profile->remote_providerID,
			notBefore, notOnOrAfter);

	if (strcmp(login->nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0) {
		/* if NameIDPolicy is 'onetime', don't use a federation */
		nameIdentifier = lasso_saml_name_identifier_new();
		nameIdentifier->content = lasso_build_unique_id(32);
		nameIdentifier->NameQualifier = LASSO_PROVIDER(profile->server)->ProviderID;
		nameIdentifier->Format = LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME;

		as = lasso_lib_authentication_statement_new_full(authenticationMethod,
				authenticationInstant, reauthenticateOnOrAfter,
				NULL, nameIdentifier);
		profile->nameIdentifier = g_strdup(nameIdentifier->content);
	} else {
		as = lasso_lib_authentication_statement_new_full(authenticationMethod,
				authenticationInstant, reauthenticateOnOrAfter,
				federation->remote_nameIdentifier,
				federation->local_nameIdentifier);
	}

	if (as == NULL) {
		return -2;
	}

	LASSO_SAML_ASSERTION(assertion)->AuthenticationStatement = 
				LASSO_SAML_AUTHENTICATION_STATEMENT(as);

	/* FIXME : How to know if the assertion must be signed or unsigned ? */
	/* signature should be added at end */
	ret = lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
			profile->server->signature_method,
			profile->server->private_key,
			profile->server->certificate);
	if (ret)
		return ret;

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		/* only add assertion if response is an AuthnResponse */
		LASSO_SAMLP_RESPONSE(profile->response)->Assertion = LASSO_SAML_ASSERTION(assertion);
	}
	/* store assertion in session object */
	if (profile->session == NULL) {
		profile->session = lasso_session_new();
	}
	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_SAML_ASSERTION(assertion));
	return 0;
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
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoFederation *federation = NULL;

	nameIDPolicy = LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy;

	if (nameIDPolicy == NULL || strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_NONE) == 0)
		return FALSE;

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0)
		return FALSE;

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED) != 0 &&
			strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "Unknown NameIDPolicy : %s", nameIDPolicy);
		/* we consider NameIDPolicy as empty (none value) if its value is unknown/invalid */
		return TRUE;
	}

	if (profile->identity != NULL) {
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (federation)
			return FALSE;
	}

	consent = LASSO_LIB_AUTHN_REQUEST(profile->request)->consent;
	if (consent == NULL)
		return TRUE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED_PRIOR) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED_CURRENT_IMPLICIT) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_OBTAINED_CURRENT_EXPLICIT) == 0)
		return FALSE;

	if (strcmp(consent, LASSO_LIB_CONSENT_UNAVAILABLE) == 0)
		return TRUE;

	if (strcmp(consent, LASSO_LIB_CONSENT_INAPPLICABLE) == 0)
		return TRUE;

	message(G_LOG_LEVEL_CRITICAL, "Unknown consent value : %s", consent);
	/* we consider consent as empty if its value is unknown/invalid */
	return TRUE;
}

/**
 * lasso_login_process_federation:
 * @login: a LassoLogin
 * @is_consent_obtained: is user consent obtained ?
 * 
 * Return value: a positive value on success or a negative if an error occurs.
 **/
static gint
lasso_login_process_federation(LassoLogin *login, gboolean is_consent_obtained)
{
	LassoFederation *federation = NULL;
	LassoProfile *profile = LASSO_PROFILE(login);
	xmlChar *nameIDPolicy;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}
	/* get nameIDPolicy in lib:AuthnRequest */
	nameIDPolicy = LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	login->nameIDPolicy = g_strdup(nameIDPolicy);

	/* if nameIDPolicy is 'onetime' => nothing to do */
	if (xmlStrEqual(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME)) {
		goto done;
	}

	/* search a federation in the identity */
	federation = g_hash_table_lookup(LASSO_PROFILE(login)->identity->federations,
			LASSO_PROFILE(login)->remote_providerID);

	if ((nameIDPolicy == NULL || xmlStrEqual(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_NONE))) {
		/* a federation MUST exist */
		if (federation == NULL) {
			/*
			 if protocolProfile is LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST
			 set StatusCode to FederationDoesNotExist in lib:AuthnResponse
			 */
			if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
				lasso_profile_set_response_status(LASSO_PROFILE(login),
						LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			}
			ret = LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
			goto done;
		}
	}
	else if (xmlStrEqual(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED) || \
			xmlStrEqual(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY)) {
		/*
		 consent is necessary, it should be obtained via consent attribute
		 in lib:AuthnRequest or IDP should ask the Principal
		 */
		if (lasso_login_must_ask_for_consent_private(login) == TRUE && is_consent_obtained == FALSE) {
			if (xmlStrEqual(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY)) {
				/*
				 if the NameIDPolicy element is 'any' and if the policy for the
				 Principal forbids federation, then evaluation MAY proceed as if the
				 value were onetime.
				 */
				g_free(login->nameIDPolicy);
				login->nameIDPolicy = g_strdup(LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME);
				goto done;
			}
			else {
				/*
				 if protocolProfile is LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST
				 set StatusCode to FederationDoesNotExist in lib:AuthnResponse
				 */
				/* FIXME : is it the correct value for the StatusCode */
				if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
					lasso_profile_set_response_status(LASSO_PROFILE(login),
							LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
				}
				ret = LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
				goto done;
			}
		}
		if (federation == NULL) {
			federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
			lasso_federation_build_local_nameIdentifier(federation,
					LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID,
					LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED,
					NULL);

			lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
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
		LASSO_PROFILE(login)->nameIdentifier = 
			LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier)->content;
	}

	return ret;
}

static gint
lasso_login_process_response_status_and_assertion(LassoLogin *login) {
	LassoProvider *idp = NULL;
	LassoSamlpResponse *response;
	char *status_value;
	int ret;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	response = LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response);

	if (response->Status == NULL || ! LASSO_IS_SAMLP_STATUS(response->Status))
		return -1;

	if (response->Status->StatusCode == NULL)
		return -1;

	status_value = response->Status->StatusCode->Value;
	if (status_value == NULL) {
		/* XXX ? was ignored before ? */ 
	}
	if (status_value && strcmp(status_value, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		return -7; /* FIXME: proper error code */
	}

	if (response->Assertion) {
		LassoProfile *profile = LASSO_PROFILE(login);
		idp = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
		if (idp == NULL)
			return LASSO_ERROR_UNDEFINED;

		/* verify signature */
		/* FIXME detect X509Data ? */
		ret = lasso_node_verify_signature(LASSO_NODE(response->Assertion),
					idp->public_key, idp->ca_cert_chain);
		if (ret < 0)
			return ret;

		/* store NameIdentifier */
		/* XXX: in AuthenticationStatement */
		profile->nameIdentifier = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
				response->Assertion->AuthenticationStatement)->Subject->NameIdentifier->content;

		if (LASSO_PROFILE(login)->nameIdentifier == NULL)
			return LASSO_ERROR_UNDEFINED;
	}

	return 0;
}

/*****************************************************************************/
/* public methods */
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
	LassoSamlAssertion *assertion = NULL;
	LassoSamlNameIdentifier *ni = NULL;
	LassoSamlNameIdentifier *idp_ni = NULL;
	LassoFederation *federation = NULL;
	LassoSamlSubjectStatementAbstract *authentication_statement;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	if (profile->identity == NULL)
		profile->identity = lasso_identity_new(); 

	if (profile->session == NULL)
		profile->session = lasso_session_new();

	if (profile->response == NULL)
		return -1;

	assertion = LASSO_SAMLP_RESPONSE(profile->response)->Assertion;
	if (assertion == NULL)
		return -1;

	lasso_session_add_assertion(profile->session, profile->remote_providerID, assertion);

	authentication_statement = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
			LASSO_SAMLP_RESPONSE(profile->response)->Assertion->AuthenticationStatement);
	ni = authentication_statement->Subject->NameIdentifier;

	if (ni == NULL)
		return -1;

	if (LASSO_IS_LIB_SUBJECT(authentication_statement->Subject)) {
		idp_ni = LASSO_LIB_SUBJECT(authentication_statement->Subject)->IDPProvidedNameIdentifier;
	}

	/* create federation, only if nameidentifier format is Federated */
	if (strcmp(ni->Format, LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED) == 0) {
		federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
		if (ni != NULL && idp_ni != NULL) {
			federation->local_nameIdentifier = ni;
			federation->remote_nameIdentifier = idp_ni;
		} else {
			federation->remote_nameIdentifier = ni;
		}
		/* add federation in identity */
		lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
	}

	return 0;
}

/**
 * lasso_login_build_artifact_msg:
 * @login: a LassoLogin
 * @authentication_result: whether the principal is authenticated.  
 * @is_consent_obtained: whether the principal consents to be federated.
 * @authenticationMethod: the authentication method
 * @authenticationInstant: the time at which the authentication took place
 * @reauthenticateOnOrAfter: the time at, or after which the service provider
 *   reauthenticates the Principal with the identity provider or NULL
 * @notBefore: the earliest time instant at which the assertion is valid
 * @notOnOrAfter: the time instant at which the assertion has expired
 *
 * @http_method: the HTTP method to send the artifact (REDIRECT or POST)
 * 
 * Builds an artifact. Depending of the HTTP method, the data for the sending of
 * the artifact are stored in msg_url (REDIRECT) or msg_url, msg_body and
 * msg_relayState (POST).
 *
 * @authenticationMethod, @authenticationInstant, @reauthenticateOnOrAfter,
 * @notBefore, @notOnOrAfter should be NULL if @authentication_result is FALSE.
 * If @authenticationInstant is NULL, the current time will be set.
 *
 * Time values must be encoded in UTC.
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_build_artifact_msg(LassoLogin *login,
		gboolean authentication_result,
		gboolean is_consent_obtained,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter,
		lassoHttpMethod http_method)
{
	/* XXX: function to check */
	LassoFederation *federation = NULL;
	LassoProvider *remote_provider;
	gchar *url;
	xmlSecByte samlArt[42], *b64_samlArt, *relayState;
	xmlChar *identityProviderSuccinctID;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (http_method != LASSO_HTTP_METHOD_REDIRECT && http_method != LASSO_HTTP_METHOD_POST) {
		message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD));
		return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
	}

	/* ProtocolProfile must be BrwsArt */
	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART) {
		message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE));
		return LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
	}

	/* process federation and build assertion only if signature is OK */
	if (LASSO_PROFILE(login)->signature_status == 0 && authentication_result == TRUE) {
		ret = lasso_login_process_federation(login, is_consent_obtained);
		if (ret < 0)
			return ret;

		/* fill the response with the assertion */
		if (ret == 0) {
			federation = g_hash_table_lookup(LASSO_PROFILE(login)->identity->federations,
					LASSO_PROFILE(login)->remote_providerID);
			lasso_login_build_assertion(login,
					federation,
					authenticationMethod,
					authenticationInstant,
					reauthenticateOnOrAfter,
					notBefore,
					notOnOrAfter);
		}
	}

	if (LASSO_PROFILE(login)->remote_providerID == NULL)
		return -1;

	/* build artifact infos */
	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	/* liberty-idff-bindings-profiles-v1.2.pdf p.25 */
	url = lasso_provider_get_metadata_one(remote_provider, "AssertionConsumerServiceURL");
	identityProviderSuccinctID = lasso_sha1(
			LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID);

	memcpy(samlArt, "\000\003", 2); /* type code */
	memcpy(samlArt+2, identityProviderSuccinctID, 20);
	lasso_build_random_sequence(samlArt+22, 20);

	xmlFree(identityProviderSuccinctID);
	b64_samlArt = xmlSecBase64Encode(samlArt, 42, 0);
	relayState = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->RelayState;

	switch (http_method) {
		case LASSO_HTTP_METHOD_REDIRECT:
			if (relayState == NULL) {
				LASSO_PROFILE(login)->msg_url = g_strdup_printf("%s?SAMLart=%s", url, b64_samlArt);
			}
			else {
				LASSO_PROFILE(login)->msg_url = g_strdup_printf("%s?SAMLart=%s&RelayState=%s",
						url, b64_samlArt, relayState);
			}
			break;
		case LASSO_HTTP_METHOD_POST:
			LASSO_PROFILE(login)->msg_url = g_strdup(url);
			LASSO_PROFILE(login)->msg_body = g_strdup(b64_samlArt);
			if (relayState != NULL) {
				LASSO_PROFILE(login)->msg_relayState = g_strdup(relayState);
			}
			break;
		default:
			break;
	}
	login->assertionArtifact = g_strdup(b64_samlArt);
	xmlFree(url);
	xmlFree(b64_samlArt);

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
lasso_login_build_authn_request_msg(LassoLogin *login, const gchar *remote_providerID)
{
	LassoProvider *provider, *remote_provider;
	xmlChar *md_authnRequestsSigned = NULL;
	xmlChar *request_protocolProfile = NULL;
	xmlChar *url = NULL;
	gchar *query = NULL;
	gchar *lareq = NULL;
	gboolean must_sign;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (remote_providerID != NULL) {
		LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);
	} else {
		LASSO_PROFILE(login)->remote_providerID = lasso_server_get_first_providerID(
				LASSO_PROFILE(login)->server);
	}

	provider = LASSO_PROVIDER(LASSO_PROFILE(login)->server);
	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	if (remote_provider == NULL) {
		return -1; /* XXX */
	}

	/* check if authnRequest must be signed */
	md_authnRequestsSigned = lasso_provider_get_metadata_one(provider, "AuthnRequestsSigned");
	must_sign = (md_authnRequestsSigned && strcmp(md_authnRequestsSigned, "true") == 0);

	/* get SingleSignOnServiceURL metadata */
	url = lasso_provider_get_metadata_one(remote_provider, "SingleSignOnServiceURL");
	if (url == NULL) {
		return -1; /* XXX */
	}

	if (login->http_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* REDIRECT -> query */
		if (must_sign) {
			query = lasso_node_export_to_query(LASSO_PROFILE(login)->request,
					LASSO_PROFILE(login)->server->signature_method,
					LASSO_PROFILE(login)->server->private_key);
			if (query == NULL) {
				message(G_LOG_LEVEL_CRITICAL,
						"Failed to create AuthnRequest query (signed).");
				ret = -3;
				goto done;
			}
		}
		else {
			query = lasso_node_export_to_query(LASSO_PROFILE(login)->request, 0, NULL);
			if (query == NULL) {
				message(G_LOG_LEVEL_CRITICAL,
						"Failed to create AuthnRequest query.");
				ret = -4;
				goto done;
			}
		}
		/* alloc msg_url (+2 for the ? and \0) */
		LASSO_PROFILE(login)->msg_url = g_strdup_printf("%s?%s", url, query);
		LASSO_PROFILE(login)->msg_body = NULL;
		g_free(query);
	}
	if (login->http_method == LASSO_HTTP_METHOD_POST) {
		/* POST -> formular */
		if (must_sign) {
#if 0 /* XXX: signatures are done differently */
			ret = lasso_samlp_request_abstract_sign_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(LASSO_PROFILE(login)->request),
					LASSO_PROFILE(login)->server->private_key,
					LASSO_PROFILE(login)->server->certificate);
#endif
		}

		if (ret < 0) {
			goto done;
		}
		lareq = lasso_node_export_to_base64(LASSO_PROFILE(login)->request);

		if (lareq != NULL) {
			LASSO_PROFILE(login)->msg_url = g_strdup(url);
			LASSO_PROFILE(login)->msg_body = lareq;
		} else {
			message(G_LOG_LEVEL_CRITICAL,
					"Failed to export AuthnRequest (Base64 encoded).");
			ret = -5;
		}
	}

done:
	xmlFree(url);
	xmlFree(request_protocolProfile);

	return ret;
}

/**
 * lasso_login_build_authn_response_msg:
 * @login: a LassoLogin
 * @authentication_result: whether the principal is authenticated
 * @is_consent_obtained: whether the principal consents to be federated
 * @authenticationMethod: the method used to authenticate the principal
 * @authenticationInstant: the time at which the authentication took place
 * @reauthenticateOnOrAfter: the time at, or after which the service provider
 *   reauthenticates the Principal with the identity provider 
 * @notBefore: the earliest time instant at which the assertion is valid
 * @notOnOrAfter: the time instant at which the assertion has expired
 * 
 * Builds an authentication response. The data for the sending of the response
 * are stored in msg_url and msg_body.
 *
 * @authenticationMethod, @authenticationInstant, @reauthenticateOnOrAfter,
 * @notBefore, @notOnOrAfter should be NULL if @authentication_result is FALSE.
 * If @authenticationInstant is NULL, the current time will be set.
 *
 * Time values must be encoded in UTC.
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_login_build_authn_response_msg(LassoLogin *login,
		gboolean authentication_result,
		gboolean is_consent_obtained,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter)
{
	LassoProvider *remote_provider;
	LassoFederation *federation;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* ProtocolProfile must be BrwsPost */
	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE));
		return LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
	}

	/* create LibAuthnResponse */
	LASSO_PROFILE(login)->response = lasso_lib_authn_response_new(
			LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID,
			LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request));

	/* if signature is not OK => modify AuthnResponse StatusCode */
	if (LASSO_PROFILE(login)->signature_status == LASSO_DS_ERROR_INVALID_SIGNATURE ||
			LASSO_PROFILE(login)->signature_status == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		switch (LASSO_PROFILE(login)->signature_status) {
			case LASSO_DS_ERROR_INVALID_SIGNATURE:
				lasso_profile_set_response_status(LASSO_PROFILE(login),
						LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
				break;
			case LASSO_DS_ERROR_SIGNATURE_NOT_FOUND: /* Unsigned AuthnRequest */
				lasso_profile_set_response_status(LASSO_PROFILE(login),
						LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST);
				break;
		}
		/* ret = LASSO_PROFILE(login)->signature_status; */
	} else {
		/* modify AuthnResponse StatusCode if user authentication is not OK */
		if (authentication_result == FALSE) {
			lasso_profile_set_response_status(LASSO_PROFILE(login),
					LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		}

		if (LASSO_PROFILE(login)->signature_status == 0 && authentication_result == TRUE) {
			/* process federation */
			ret = lasso_login_process_federation(login, is_consent_obtained);
			/* fill the response with the assertion */
			if (ret == 0) {
				federation = g_hash_table_lookup(
						LASSO_PROFILE(login)->identity->federations,
						LASSO_PROFILE(login)->remote_providerID);
				lasso_login_build_assertion(login,
						federation,
						authenticationMethod,
						authenticationInstant,
						reauthenticateOnOrAfter,
						notBefore,
						notOnOrAfter);
			}
			else if (ret < 0) {
				return ret;
			}
		}
	}

	if (LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response)->Status == NULL) {
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_SAML_STATUS_CODE_SUCCESS);
	}

	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	/* build an lib:AuthnResponse base64 encoded */
	LASSO_PROFILE(login)->msg_body = lasso_node_export_to_base64(LASSO_PROFILE(login)->response);
	LASSO_PROFILE(login)->msg_url = lasso_provider_get_metadata_one(
			remote_provider, "AssertionConsumerServiceURL");

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
#if 0 /* XXX: signatures are done differently */
	ret = lasso_samlp_request_abstract_sign_signature_tmpl(
			LASSO_SAMLP_REQUEST_ABSTRACT(LASSO_PROFILE(login)->request),
			LASSO_PROFILE(login)->server->private_key,
			LASSO_PROFILE(login)->server->certificate);
#endif
	LASSO_PROFILE(login)->msg_body = lasso_node_export_to_soap(LASSO_PROFILE(login)->request);

	/* get msg_url (SOAP Endpoint) */
	remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
	if (err != NULL) {
		goto done;
	}
	LASSO_PROFILE(login)->msg_url = lasso_provider_get_metadata_one(
			remote_provider, "SoapEndpoint");
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
 * Return value: 0 on success or a negative value if an 
 **/
gint
lasso_login_build_response_msg(LassoLogin *login, gchar *remote_providerID)
{
	LassoProvider *remote_provider;
	LassoSamlAssertion *assertion;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), -1);

	LASSO_PROFILE(login)->response = lasso_samlp_response_new();

	if (remote_providerID != NULL) {
		LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);
		remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
		/* FIXME verify the SOAP request signature */
		ret = lasso_node_verify_signature(LASSO_PROFILE(login)->request,
				remote_provider->public_key,
				remote_provider->ca_cert_chain);
		/* changed status code into RequestDenied
		 if signature is invalid or not found
		 if an error occurs during verification */
		if (ret != 0) {
			lasso_profile_set_response_status(LASSO_PROFILE(login),
					LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		}

		if (LASSO_PROFILE(login)->session) {
			/* get assertion in session and add it in response */
			assertion = lasso_session_get_assertion(LASSO_PROFILE(login)->session,
					LASSO_PROFILE(login)->remote_providerID);
			if (assertion == NULL) {
				/* FIXME should this message output by lasso_session_get_assertion () ? */
				message(G_LOG_LEVEL_CRITICAL, "Assertion not found in session");
			}
			LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response)->Assertion =
				g_object_ref(assertion);
		}
	} else {
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
	}

	LASSO_PROFILE(login)->msg_body = lasso_node_export_to_soap(LASSO_PROFILE(login)->response);

	return ret;
}

/**
 * lasso_login_destroy:
 * @login: a LassoLogin
 * 
 * Destroys LassoLogin objects created with lasso_login_new() or lasso_login_new_from_dump().
 **/
void
lasso_login_destroy(LassoLogin *login)
{
	g_object_unref(G_OBJECT(login));
}

gint
lasso_login_init_authn_request(LassoLogin *login, lassoHttpMethod http_method)
{
	LassoLibAuthnRequest *request;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (http_method != LASSO_HTTP_METHOD_REDIRECT && http_method != LASSO_HTTP_METHOD_POST) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD));
		return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
	}

	login->http_method = http_method;


	/* XXX: should be moved somehow in samlp_request_abstract.c */
	request = lasso_lib_authn_request_new();
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID = lasso_build_unique_id(32);
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->IssueInstant = lasso_get_current_time();
	request->ProviderID = g_strdup(LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID);

	if (http_method == LASSO_HTTP_METHOD_POST) {
		/* XXX: if post sign_type/sign_method
		   LASSO_SIGNATURE_TYPE_WITHX509,
		   LASSO_SIGNATURE_METHOD_RSA_SHA1);
		   */
	}

	LASSO_PROFILE(login)->request = LASSO_NODE(request);

	if (LASSO_PROFILE(login)->request == NULL) {
		return -2;
	}

	return 0;
}

gint
lasso_login_init_request(LassoLogin *login, gchar *response_msg,
		lassoHttpMethod response_http_method)
{
	char **query_fields;
	gint ret = 0;
	int i;
	char *artifact_b64, *provider_succint_id_b64;
	char provider_succint_id[21], assertion_handle[21];
	char artifact[43];
	LassoSamlpRequestAbstract *request;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* rebuild response (artifact) */
	switch (response_http_method) {
		case LASSO_HTTP_METHOD_REDIRECT: /* artifact by REDIRECT */
			query_fields = urlencoded_to_strings(response_msg);
			for (i=0; query_fields[i]; i++) {
				if (strncmp(query_fields[i], "SAMLart=", 8) != 0) {
					free(query_fields[i]);
					continue;
				}
				artifact_b64 = strdup(query_fields[i]+8);
				free(query_fields[i]);
			}
			free(query_fields);
			break;
		case LASSO_HTTP_METHOD_POST:
			/* artifact by POST */
			g_assert_not_reached();
			/* XXX: artifact code should be moved in this file
			response = lasso_artifact_new_from_lares(response_msg, NULL);
			*/
			break;
		default:
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD));
			return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
	}

	i = xmlSecBase64Decode(artifact_b64, artifact, 43);
	if (i < 0 || i > 42) {
		free(artifact_b64);
		return -1;
	}

	if (artifact[0] != 0 || artifact[1] != 3) { /* wrong type code */
		free(artifact_b64);
		return -1;
	}

	memcpy(provider_succint_id, artifact+2, 20);
	provider_succint_id[20] = 0;
	memcpy(assertion_handle, artifact+22, 20);
	assertion_handle[20] = 0;

	provider_succint_id_b64 = xmlSecBase64Encode(provider_succint_id, 20, 0);

	LASSO_PROFILE(login)->remote_providerID = lasso_server_get_providerID_from_hash(
			LASSO_PROFILE(login)->server, provider_succint_id_b64);
	xmlFree(provider_succint_id_b64);

	request = LASSO_SAMLP_REQUEST_ABSTRACT(g_object_new(LASSO_TYPE_SAMLP_REQUEST, NULL));
	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();

	LASSO_SAMLP_REQUEST(request)->AssertionArtifact = artifact_b64;

	LASSO_PROFILE(login)->request = LASSO_NODE(request);

	
	return ret;
}

/**
 * lasso_login_init_idp_initiated_authn_request:
 * @login: a LassoLogin.
 * @remote_providerID: the providerID of the remote service provider (may be NULL).
 * 
 * It's possible for an identity provider to generate an authentication response without first
 * having received an authentication request. This method must be used in this case.
 *
 * If @remote_providerID is NULL, the providerID of the first provider found in server is used.
 * 
 * Return value: 0 on success and a negative value if an error occurs.
 **/
gint
lasso_login_init_idp_initiated_authn_request(LassoLogin *login,
		const gchar *remote_providerID)
{
	LassoLibAuthnRequest *request;
	gchar *first_providerID;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	/* if remote_providerID is NULL, get first providerID in server */

	/* store providerID of the service provider */
	if (remote_providerID == NULL) {
		first_providerID = lasso_server_get_first_providerID(LASSO_PROFILE(login)->server);
		LASSO_PROFILE(login)->remote_providerID = first_providerID;
	}
	else {
		LASSO_PROFILE(login)->remote_providerID = g_strdup(remote_providerID);
	}

	/* build self-addressed lib:AuthnRequest */
	request = lasso_lib_authn_request_new(); /* XXX */
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID = lasso_build_unique_id(32);
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	LASSO_SAMLP_REQUEST_ABSTRACT(request)->IssueInstant = lasso_get_current_time();
	request->ProviderID = g_strdup(LASSO_PROFILE(login)->remote_providerID);

	request->NameIDPolicy = LASSO_LIB_NAMEID_POLICY_TYPE_ANY;

	/* remove RequestID attribute else it would be used in response assertion */
	LASSO_SAMLP_REQUEST_ABSTRACT(LASSO_PROFILE(login)->request)->RequestID = NULL;

	LASSO_PROFILE(login)->request = LASSO_NODE(request);

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
	if (lasso_login_must_ask_for_consent_private(login)) {
		if (LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->IsPassive)
			return FALSE;
		return TRUE;
	}
	return FALSE;
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
	gboolean must_authenticate = FALSE;
	LassoLibAuthnRequest *request;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request);

	/* verify if the user must be authenticated or not */

	/* get IsPassive and ForceAuthn in AuthnRequest if exists */

	if ((request->ForceAuthn || LASSO_PROFILE(login)->session == NULL) && \
			request->IsPassive == FALSE) {
		must_authenticate = TRUE;
	}
	else if (LASSO_PROFILE(login)->identity == NULL && \
			request->IsPassive && \
			login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_LIB_STATUS_CODE_NO_PASSIVE);
	}

	return must_authenticate;
}

gint
lasso_login_process_authn_request_msg(LassoLogin *login, gchar *authn_request_msg)
{
	lassoHttpMethod authn_request_http_method; /* XXX update to current CVS code */
	LassoProvider *remote_provider;
	gchar *protocolProfile;
	xmlChar *md_authnRequestsSigned;
	gboolean must_verify_signature = FALSE;
	gint ret = 0;
	LassoLibAuthnRequest *request;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (authn_request_msg == NULL) {
		authn_request_http_method = LASSO_HTTP_METHOD_IDP_INITIATED;
		if (LASSO_PROFILE(login)->request == NULL) {
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_PROFILE_ERROR_MISSING_REQUEST));
			return LASSO_PROFILE_ERROR_MISSING_REQUEST;
		}

		/* LibAuthnRequest already set by lasso_login_init_idp_initiated_authn_request() */
		request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
		
		/* verify that NameIDPolicy is 'any' */
		if (request->NameIDPolicy == NULL)
			return LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
			
		if (strcmp(request->NameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0)
			return LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
	} else {
		request = lasso_lib_authn_request_new();
		lasso_node_init_from_message(LASSO_NODE(request), authn_request_msg);
		
		LASSO_PROFILE(login)->request = LASSO_NODE(request);
	}


	/* get ProtocolProfile in lib:AuthnRequest */
	protocolProfile = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->ProtocolProfile;
	if (protocolProfile == NULL ||
			xmlStrEqual(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART)) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
	}
	else if (xmlStrEqual(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST)) {
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
	}
	else {
		message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE));
		return LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
	}

	/* get remote ProviderID */
	LASSO_PROFILE(login)->remote_providerID = g_strdup(
			LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->ProviderID);

	/* Check authnRequest signature. */
	if (authn_request_http_method != LASSO_HTTP_METHOD_IDP_INITIATED) {
		remote_provider = g_hash_table_lookup(LASSO_PROFILE(login)->server->providers,
			LASSO_PROFILE(login)->remote_providerID);
		if (remote_provider != NULL) {
			/* Is authnRequest signed ? */
			md_authnRequestsSigned = lasso_provider_get_metadata_one(
					remote_provider, "AuthnRequestsSigned");
			if (md_authnRequestsSigned != NULL) {
				must_verify_signature = xmlStrEqual(md_authnRequestsSigned, "true");
				g_free(md_authnRequestsSigned);
			} else {
				/* AuthnRequestsSigned element is required */
				message(G_LOG_LEVEL_CRITICAL, "XXX");
				return -1;
			}
		} else {
			message(G_LOG_LEVEL_CRITICAL, "Must sign without knowing provider");
			return -1;
		}

		/* verify request signature */
		if (must_verify_signature) {
			ret = lasso_provider_verify_signature(remote_provider,
					authn_request_msg, "RequestID");
			LASSO_PROFILE(login)->signature_status = ret;
		}
	}

	return ret;
}

gint
lasso_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg)
{
	gint ret1 = 0, ret2 = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(authn_response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	LASSO_PROFILE(login)->response = lasso_lib_authn_response_new(NULL, NULL);
	lasso_node_init_from_message(LASSO_PROFILE(login)->response, authn_response_msg);

	LASSO_PROFILE(login)->remote_providerID = g_strdup(
			LASSO_LIB_AUTHN_RESPONSE(LASSO_PROFILE(login)->response)->ProviderID);

	if (LASSO_PROFILE(login)->remote_providerID == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
	}

	LASSO_PROFILE(login)->msg_relayState = g_strdup(LASSO_LIB_AUTHN_RESPONSE(
			LASSO_PROFILE(login)->response)->RelayState);

	ret2 = lasso_login_process_response_status_and_assertion(login);

	return ret2 == 0 ? ret1 : ret2;
}

gint
lasso_login_process_request_msg(LassoLogin *login, gchar *request_msg)
{
	gint ret = 0;
	LassoProfile *profile = LASSO_PROFILE(login);

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* rebuild samlp:Request with request_msg */
	profile->request = lasso_node_new_from_soap(request_msg);
	/* XXX was: lasso_request_new_from_export(request_msg, LASSO_NODE_EXPORT_TYPE_SOAP); */
	if (profile->request == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to rebuild samlp:Request with request message.");
		return LASSO_ERROR_UNDEFINED;
	}
	/* get AssertionArtifact */
	login->assertionArtifact = g_strdup(
			LASSO_SAMLP_REQUEST(profile->request)->AssertionArtifact);

	return ret;
}

gint
lasso_login_process_response_msg(LassoLogin *login, gchar *response_msg)
{
	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* rebuild samlp:Response with response_msg */
	LASSO_PROFILE(login)->response = lasso_node_new_from_soap(response_msg);
	if (! LASSO_IS_SAMLP_RESPONSE(LASSO_PROFILE(login)->response) ) {
		LASSO_PROFILE(login)->response = NULL;
		message(G_LOG_LEVEL_CRITICAL, "Failed to rebuild samlp:Response from message.");
		return LASSO_ERROR_UNDEFINED;
	}

	return lasso_login_process_response_status_and_assertion(login);
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLogin *login = LASSO_LOGIN(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "Login");
	xmlSetProp(xmlnode, "LoginDumpVersion", "2");

	if (login->assertionArtifact)
		xmlNewTextChild(xmlnode, NULL, "AssertionArtifact", login->assertionArtifact);

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART)
		xmlNewTextChild(xmlnode, NULL, "ProtocolProfile", "Artifact");
	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST)
		xmlNewTextChild(xmlnode, NULL, "ProtocolProfile", "POST");

	if (login->nameIDPolicy)
		xmlNewTextChild(xmlnode, NULL, "NameIDPolicy", login->nameIDPolicy);

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLogin *login = LASSO_LOGIN(node);
	xmlNode *t;

	parent_class->init_from_xml(node, xmlnode);

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "AssertionArtifact") == 0)
			login->assertionArtifact = xmlNodeGetContent(t);
		if (strcmp(t->name, "NameIDPolicy") == 0)
			login->nameIDPolicy = xmlNodeGetContent(t);
		if (strcmp(t->name, "ProtocolProfile") == 0) {
			char *s;
			s = xmlNodeGetContent(t);
			if (strcmp(s, "Artifact") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
			if (strcmp(s, "POST") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
			xmlFree(s);
		}
		t = t->next;
	}
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoLogin *login = LASSO_LOGIN(object);

	if (login->private->dispose_has_run == TRUE) {
		return;
	}
	login->private->dispose_has_run = TRUE;

	debug("Login object 0x%x disposed ...", login);

	/* unref reference counted objects */

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoLogin *login = LASSO_LOGIN(object);

	debug("Login object 0x%x finalized ...", login);
	g_free(login->assertionArtifact);
	g_free(login->private);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoLogin *login)
{
	login->private = g_new (LassoLoginPrivate, 1);
	login->private->dispose_has_run = FALSE;

	login->protocolProfile = 0;
	login->assertionArtifact = NULL;
}

static void
class_init(LassoLoginClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_login_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoLoginClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLogin),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoLogin", &this_info, 0);
	}
	return this_type;
}

LassoLogin*
lasso_login_new(LassoServer *server)
{
	LassoLogin *login = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	login = g_object_new(LASSO_TYPE_LOGIN, NULL);
	LASSO_PROFILE(login)->server = server;

	return login;
}

LassoLogin*
lasso_login_new_from_dump(LassoServer *server, const gchar *dump)
{
	LassoLogin *login;
	xmlDoc *doc;

	login = g_object_new(LASSO_TYPE_LOGIN, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(login), xmlDocGetRootElement(doc)); 
	LASSO_PROFILE(login)->server = server;

	return login;
}

gchar*
lasso_login_dump(LassoLogin *login)
{
	return lasso_node_dump(LASSO_NODE(login), NULL, 1);
}

