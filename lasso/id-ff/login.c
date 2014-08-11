/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * SECTION:login
 * @short_description: Single Sign-On and Federation Profile
 *
 * The Single Sign On process allows a user to log in once to an identity
 * provider (IdP), and to be then transparently loged in to the required
 * service providers (SP) belonging to the IP "circle of trust".  Subordinating
 * different identities of the same user within a circle of trust to a unique
 * IP is called "Identity Federation".  The liberty Alliance specifications
 * allows, thanks to this federation, strong and unique authentication coupled
 * with control by the user of his personal informations. The explicit user
 * agreement is necessary before proceeding to Identity Federation.
 *
 * <para>
 * The service provider must implement the following process:
 * <itemizedlist>
 *  <listitem><para>creating an authentication request with
 *  lasso_login_init_authn_request();</para></listitem>
 *  <listitem><para>sending it to the identity provider with
 *  lasso_login_build_authn_request_msg();</para></listitem>
 *  <listitem><para>receiving and processing the answer:
 *    <itemizedlist>
 *      <listitem>either an authentication response with
 *      lasso_login_process_authn_response_msg()</listitem>
 *      <listitem>or an artifact with lasso_login_init_request() then sending the
 *      request to the IdP with lasso_login_build_request_msg() and processing the
 *      new answer with lasso_login_process_response_msg().</listitem>
 *    </itemizedlist>
 *    </para></listitem>
 * </itemizedlist>
 * </para>
 *
 * <para>Our first example shows how to initiate a request toward an ID-FF 1.2 or SAML 2.0 identity
 * provider. It supposes that we already initialized a #LassoServer object with the metadatas or our
 * provider (and its private key if we want to sign the request), and that we added the metadatas of
 * the targetted IdP with the method lasso_server_add_provider().  </para>
 *
 * <example>
 * <title>Service Provider Login URL</title>
 * <programlisting>
 * LassoLogin *login;
 * int rc; // hold return codes
 *
 * login = lasso_login_new(server);
 * rc = lasso_login_init_authn_request(login, "http://identity-provider-id/",
 *                 LASSO_HTTP_METHOD_REDIRECT);
 * if (rc != 0) {
 *   ... // handle errors, most of them are related to bad initialization
 * }
 *
 * // customize AuthnRequest
 * // protocolProfile is the protocolProfile of the provider http://identity-provider-id/
 * if (protocolProfile == LASSO_LIBERTY_1_2) {
 *         LassoLibAuthnRequest *request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
 *         request->NameIDPolicy = strdup(LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED);
 *         request->ForceAuthn = TRUE;
 *         request->IsPassive = FALSE;
 *         // tell the IdP how to return the response
 *         request->ProtocolProfile = strdup(LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART);
 * } else if (protocolProfile == LASSO_SAML_2_0) {
 *         LassoSamlp2AuthnRequest *request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
 *         if (request->NameIDPolicy->Format) {
 *                 g_free(request->NameIDPolicy->Format);
 *         }
 *         request->NameIDPolicy->Format = g_strdup(LASSO_NAME_IDENTIFIER_FORMAT_PERSISTENT);
 *         // Allow creation of new federation
 *         // 
 *         request->NameIDPolicy->AllowCreate = 1;
 *         request->ForceAuthn = TRUE;
 *         request->IsPassive = FALSE;
 *         // tell the IdP how to return the response
 *         if (request->ProtocolBinding) {
 *                  g_free(request->ProtocolBinding);
 *         }
 *         // here we expect an artifact response, it could be post, redirect or PAOS.
 *         request->ProtocolBinding = g_strdup(LASSO_SAML2_METADATA_BINDING_ARTIFACT);
   }
 * // Lasso will choose whether to sign the request by looking at the IdP
 * // metadatas and at our metadatas, but you can always force him to sign or to
 * // not sign using the method lasso_profile_set_signature_hint() on the
 * // LassoLogin object.
 *
 * rc = lasso_login_build_authn_request_msg(login);
 * if (rc != 0) {
      .... // handle errors
      // could be that the requested binding (POST, Redirect, etc..) is not supported (LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE)
      // or that we could not sign the request (LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED).
 * }
 *
 * // redirect user to identity provider
   // we chose the Redirect binding, so we have to generate a redirect HTTP response to the URL returned by Lasso
 * printf("Location: %s\n\nRedirected to IdP\n", LASSO_PROFILE(login)->msg_url);
 * </programlisting>
 * </example>
 *
 * <para>Next example shows how to receive the response from the identity
 * provider for ID-FF 1.2.</para>
 *
 * <example>
 * <title>Service Provider Assertion Consumer Service URL for ID-FF 1.2</title>
 * <programlisting>
 * LassoLogin *login;
 * char *request_method = getenv("REQUEST_METHOD");
 * char *artifact_msg = NULL, *lares = NULL, *lareq = NULL;
 * char *name_identifier;
 * lassoHttpMethod method;
 * int rc = 0;
 *
 * login = lasso_login_new(server);
 * if (strcmp(request_method, "GET") == 0) {
 *         artifact_msg = getenv("QUERY_STRING");
 *         method = LASSO_HTTP_METHOD_REDIRECT;
 * } else {
 *         // read submitted form; if it has a LAREQ field, put it in lareq,
 *         // if it has a LARES field, put it in lares
 *         if (lareq) {
 *                 artifact_msg = lareq;
 *         } else if (lares) {
 *                 response_msg = lares;
 *         } else {
 *                 // bail out
 *         }
 *         method = LASSO_HTTP_METHOD_POST;
 * }
 *
 * if (artifact_msg) {
 *         // we received an artifact response,
 *         // it means we did not really receive the response,
 *         // only a token to redeem the real response from the identity
 *         // provider through a SOAP resolution call
 *         rc = lasso_login_init_request(login, artifact_msg, method);
 *         if (rc != 0) {
 *                   ... // handle errors
 *                   // there is usually no error at this step, only
 *                   // if the IdP response is malformed
 *         }
 *         rc = lasso_login_build_request_msg(login);
 *         if (rc != 0) {
 *                   ... // handle errors
 *                   // as for AuthnRequest generation, it generally is caused
 *                   // by a bad initialization like an impossibility to load
 *                   // the private key.
 *         }
 *         // makes a SOAP call, soap_call is NOT a Lasso function
 *         soap_answer_msg = soap_call(LASSO_PROFILE(login)->msg_url,
 *                         LASSO_PROFILE(login)->msg_body);
 *         rc = lasso_login_process_response_msg(login, soap_answer_msg);
 *         if (rc != 0) {
 *                   ... // handle errors
 *                   // here you can know if the IdP refused the request, 
 *         }
 * } else if (response_msg) {
 *         lasso_login_process_authn_response_msg(login, response_msg);
 * }
 *
 * // looks up name_identifier in local file, database, whatever and gets back
 * // two things: identity_dump and session_dump
 * name_identifier = LASSO_PROFILE(login)->nameIdentifier
 * lasso_profile_set_identity_from_dump(LASSO_PROFILE(login), identity_dump);
 * lasso_profile_set_session_from_dump(LASSO_PROFILE(login), session_dump);
 *
 * lasso_login_accept_sso(login);
 *
 * if (lasso_profile_is_identity_dirty(LASSO_PROFILE(login))) {
 *         LassoIdentity *identity;
 *         char *identity_dump;
 *         identity = lasso_profile_get_identity(LASSO_PROFILE(login));
 *         identity_dump = lasso_identity_dump(identity);
 *         // record identity_dump in file, database...
 * }
 *
 * if (lasso_profile_is_session_dirty(LASSO_PROFILE(login))) {
 *         LassoSession *session;
 *         char *session_dump;
 *         session = lasso_profile_get_session(LASSO_PROFILE(login));
 *         session_dump = lasso_session_dump(session);
 *         // record session_dump in file, database...
 * }
 *
 * // redirect user anywhere
 * printf("Location: %s\n\nRedirected to site root\n", login->msg_url);
 * </programlisting>
 * </example>
 *
 * <para>The implement an IdP you must create a single sign-on service endpoint, the needed APIs for
 * this are lasso_login_process_authn_request_msg(), lasso_login_validate_request_msg(),
 * lasso_login_build_assertion(), lasso_login_build_authn_response_msg() and
 * lasso_login_build_artifact_msg(). You will have to chose between
 * lasso_login_build_authn_response_msg() and lasso_login_build_artifact_msg() depending on the
 * requested protocol for the response by the service provider</para>
 *
 * <example>
 * <title>Identity provider single sign-on service</title>
 * <programlisting>
 * LassoLogin *login;
 * char *request_method = getenv("REQUEST_METHOD");
 * char *artifact_msg = NULL, *lares = NULL, *lareq = NULL;
 * char *name_identifier;
 * lassoHttpMethod method;
 * int rc = 0;
 *
 * login = lasso_login_new(server);
 * if (strcmp(request_method, 'GET')) { // AuthnRequest send with the HTTP-Redirect binding
 *     //
 *     lasso_profile_set_signature_verify_hint(LASSO_PROFILE(login),
 *             LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE);
 *     rc = lasso_process_authn_request_msg(login, getenv("QUERY_STRING"));
 *     if (rc != 0) {
 *         // handle errors
 *     }
 *
 *
 * } else {
 *
 * </programlisting>
 * </example>
 *
 */

#include <xmlsec/base64.h>

#include <config.h>
#include "lasso_config.h"
#include "../utils.h"
#include "../debug.h"
#include "login.h"
#include "provider.h"
#include "../xml/private.h"
#include "../xml/lib_authentication_statement.h"
#include "../xml/lib_subject.h"
#include "../xml/saml_advice.h"
#include "../xml/saml_attribute.h"
#include "../xml/saml_attribute_value.h"
#include "../xml/saml_audience_restriction_condition.h"
#include "../xml/saml_conditions.h"
#include "../xml/samlp_response.h"
#include "../xml/saml-2.0/saml2_encrypted_element.h"
#include "../xml/misc_text_node.h"


#include "profileprivate.h"
#include "providerprivate.h"
#include "serverprivate.h"
#include "sessionprivate.h"
#include "identityprivate.h"
#include "loginprivate.h"
#include "../saml-2.0/loginprivate.h"
#include "../lasso_config.h"

#ifdef LASSO_WSF_ENABLED
#include "../id-wsf/id_ff_extensions_private.h"
#endif

#define LASSO_LOGIN_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_LOGIN, LassoLoginPrivate))


static void lasso_login_build_assertion_artifact(LassoLogin *login);

/*****************************************************************************/
/* static methods/functions */
/*****************************************************************************/

/**
 * lasso_login_build_assertion:
 * @login: a #LassoLogin
 * @authenticationMethod: the authentication method
 * @authenticationInstant: the time at which the authentication took place
 * @notBefore: the earliest time instant at which the assertion is valid
 * @notOnOrAfter: the time instant at which the assertion has expired
 *
 * Builds an assertion and stores it in profile session.
 * @authenticationInstant, reauthenticateOnOrAfter, @notBefore and
 * @notOnOrAfter may be NULL.  If @authenticationInstant is NULL, the current
 * time will be used.  Time values must be encoded in UTC.
 *
 * Construct the authentication assertion for the response. It must be called after validating the
 * request using lasso_login_validate_request_msg(). The created assertion is accessed using
 * lasso_login_get_assertion().
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>
 * #LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND if no identity object was found in the login profile object.
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_MISSING_RESPONSE if no response object is present ( it is normally initialized
 * by lasso_login_process_authn_request_msg() )
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND if a #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT or #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED NameID format is asked and no corresponding federation was found in the #LassoIdentity object,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if encryption is needed and the request issuing provider is unknown (it as not been registered in the #LassoServer object),
 * </para></listitem>
 * <listitem><para>
 * #LASSO_DS_ERROR_ENCRYPTION_FAILED if encryption is needed but it failed,
 * </para></listitem>
 * </itemizedlist>
 *
 **/
int
lasso_login_build_assertion(LassoLogin *login,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter)
{
	LassoSamlAssertion *assertion;
	LassoLibAuthenticationStatement *as;
	LassoSamlNameIdentifier *nameIdentifier = NULL;
	LassoProfile *profile;
	LassoFederation *federation;
	LassoProvider *provider = NULL;
	LassoSaml2EncryptedElement *encrypted_element = NULL;
	LassoSamlSubjectStatementAbstract *ss;
	lasso_error_t rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	if (profile->identity == NULL)
		return LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND;

	IF_SAML2(profile) {
		return lasso_saml20_login_build_assertion(login,
				authenticationMethod, authenticationInstant,
				notBefore, notOnOrAfter);
	}

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);

	assertion = LASSO_SAML_ASSERTION(lasso_lib_assertion_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->RequestID,
			profile->remote_providerID, notBefore, notOnOrAfter));

	if (strcmp(login->nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0 ||
			federation == NULL) {
		/* if NameIDPolicy is 'onetime', don't use a federation */
		nameIdentifier = lasso_saml_name_identifier_new();
		lasso_assign_new_string(nameIdentifier->content, lasso_build_unique_id(32));
		lasso_assign_string(nameIdentifier->NameQualifier,
				LASSO_PROVIDER(profile->server)->ProviderID);
		lasso_assign_string(nameIdentifier->Format,
				LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME);

		as = lasso_lib_authentication_statement_new_full(authenticationMethod,
				authenticationInstant, reauthenticateOnOrAfter,
				NULL, nameIdentifier);
		lasso_assign_new_gobject(profile->nameIdentifier, LASSO_NODE(nameIdentifier));
	} else {
		as = lasso_lib_authentication_statement_new_full(authenticationMethod,
				authenticationInstant, reauthenticateOnOrAfter,
				LASSO_SAML_NAME_IDENTIFIER(federation->remote_nameIdentifier),
				LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));
	}

	/* Encrypt NameID */
	provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(as);
	if (provider
			&& (lasso_provider_get_encryption_mode(provider) & LASSO_ENCRYPTION_MODE_NAMEID)) {
		encrypted_element = LASSO_SAML2_ENCRYPTED_ELEMENT(lasso_node_encrypt(
					LASSO_NODE(ss->Subject->NameIdentifier),
					lasso_provider_get_encryption_public_key(provider),
					lasso_provider_get_encryption_sym_key_type(provider),
					provider->ProviderID));
		if (encrypted_element != NULL) {
			lasso_assign_new_gobject(ss->Subject->EncryptedNameIdentifier, encrypted_element);
			lasso_release_gobject(ss->Subject->NameIdentifier);
		}
	}

	/* add session index */
	if (lasso_provider_get_first_http_method(&login->parent.server->parent,
				provider, LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT) != LASSO_HTTP_METHOD_NONE) {
		lasso_assign_string(as->SessionIndex, assertion->AssertionID);
	}

	assertion->AuthenticationStatement = LASSO_SAML_AUTHENTICATION_STATEMENT(as);

	/* Save signing material in assertion private datas to be able to sign later */
	lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(login->parent.server,
			profile->remote_providerID, (LassoNode*)assertion));

	lasso_list_add_gobject(LASSO_SAMLP_RESPONSE(profile->response)->Assertion,
			assertion);

#ifdef LASSO_WSF_ENABLED
	lasso_login_assertion_add_discovery(login, assertion);
#endif

	/* store assertion in session object */
	if (profile->session == NULL) {
		profile->session = lasso_session_new();
	}
	lasso_assign_gobject(login->assertion, LASSO_SAML_ASSERTION(assertion));
	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_NODE(assertion));

	if (LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MajorVersion == 1 &&
			LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MinorVersion < 2) {
		/* pre-id-ff 1.2, saml 1.0 */

		/* needs assertion artifact */
		lasso_login_build_assertion_artifact(login);

		assertion->MinorVersion = 0;

		ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement);
		ss->Subject = LASSO_SAML_SUBJECT(lasso_saml_subject_new());
		ss->Subject->NameIdentifier = g_object_ref(profile->nameIdentifier);
		ss->Subject->SubjectConfirmation = lasso_saml_subject_confirmation_new();
		/* liberty-architecture-bindings-profiles-v1.1.pdf, page 24, line 729 */
		lasso_list_add_string(ss->Subject->SubjectConfirmation->ConfirmationMethod,
			LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01);
		lasso_assign_string(ss->Subject->SubjectConfirmation->SubjectConfirmationData,
			login->assertionArtifact);

		if (nameIdentifier) {
			/* draft-liberty-idff-protocols-schemas-1.2-errata-v2.0.pdf */
			lasso_release_string(nameIdentifier->NameQualifier);
			lasso_release_string(nameIdentifier->Format);
		}
	}

cleanup:
	lasso_release_gobject(assertion);
	return rc;
}

/**
 * lasso_login_must_ask_for_consent_private:
 * @login: a #LassoLogin
 *
 * Evaluates if it is necessary to ask the consent of the Principal.
 * This method doesn't take the isPassive value into account.
 *
 * Return value: TRUE if consent should be asked, FALSE otherwise.
 **/
static gboolean
lasso_login_must_ask_for_consent_private(LassoLogin *login)
{
	char *nameIDPolicy, *consent;
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoFederation *federation = NULL;

	nameIDPolicy = LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy;

	if (nameIDPolicy == NULL || strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_NONE) == 0)
		return FALSE;

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0)
		return FALSE;

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED) != 0 &&
			strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "Unknown NameIDPolicy: %s", nameIDPolicy);
		/* NameIDPolicy is considered empty (None value) if its value is unknown/invalid */
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

	message(G_LOG_LEVEL_CRITICAL, "Unknown consent value: %s", consent);
	/* we consider consent as empty if its value is unknown/invalid */
	return TRUE;
}

/**
 * lasso_login_process_federation:
 * @login: a #LassoLogin
 * @is_consent_obtained: whether user consent has been obtained
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
static gint
lasso_login_process_federation(LassoLogin *login, gboolean is_consent_obtained)
{
	LassoFederation *federation = NULL;
	LassoProfile *profile;
	char *nameIDPolicy;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}

	/* get nameIDPolicy in lib:AuthnRequest */
	nameIDPolicy = LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy;
	if (nameIDPolicy == NULL)
		nameIDPolicy = LASSO_LIB_NAMEID_POLICY_TYPE_NONE;
	lasso_assign_string(login->nameIDPolicy, nameIDPolicy);

	/* if nameIDPolicy is 'onetime' => nothing to do */
	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME) == 0) {
		return 0;
	}

	/* search a federation in the identity */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_NONE) == 0) {
		/* a federation MUST exist */
		if (federation == NULL) {
			/* if protocolProfile is LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST
			 * set StatusCode to FederationDoesNotExist in lib:AuthnResponse
			 */
			lasso_profile_set_response_status(LASSO_PROFILE(login),
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
		}

		lasso_assign_gobject(LASSO_PROFILE(login)->nameIdentifier,
			LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));
		return 0;
	}

	if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED) != 0 &&
			strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) != 0) {
		return critical_error(LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY);
	}

	/* consent is necessary, it should be obtained via consent attribute
	 * in lib:AuthnRequest or IDP should ask the Principal
	 */
	if (lasso_login_must_ask_for_consent_private(login) && !is_consent_obtained) {
		if (strcmp(nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ANY) == 0) {
			/* if the NameIDPolicy element is 'any' and if the policy
			 * for the Principal forbids federation, then evaluation
			 * MAY proceed as if the value was 'onetime'.
			 */
			lasso_assign_string(login->nameIDPolicy, LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME);
			return 0;
		}

		/* if protocolProfile is LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST
		 * set StatusCode to FederationDoesNotExist in lib:AuthnResponse
		 */
		/* FIXME : is it the correct value for the StatusCode ? */
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
	}

	if (federation == NULL) {
		federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
		lasso_federation_build_local_name_identifier(federation,
				LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID,
				LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED,
				NULL);
		lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
	}

	lasso_assign_gobject(LASSO_PROFILE(login)->nameIdentifier,
		LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier));

	return ret;
}

static gint
lasso_login_process_response_status_and_assertion(LassoLogin *login)
{
	LassoProvider *idp;
	LassoSamlpResponse *response;
	char *status_value;
	LassoSamlSubjectStatementAbstract *sssa = NULL;
	LassoSamlSubjectStatementAbstract *sas = NULL;
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	response = LASSO_SAMLP_RESPONSE(LASSO_PROFILE(login)->response);

	if (response->Status == NULL || ! LASSO_IS_SAMLP_STATUS(response->Status) ||
			response->Status->StatusCode == NULL ||
			response->Status->StatusCode->Value == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}

	status_value = response->Status->StatusCode->Value;
	if (status_value && strcmp(status_value, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		if (strcmp(status_value, LASSO_SAML_STATUS_CODE_REQUEST_DENIED) == 0)
			return LASSO_LOGIN_ERROR_REQUEST_DENIED;
		if (strcmp(status_value, LASSO_SAML_STATUS_CODE_RESPONDER) == 0) {
			/* samlp:Responder */
			if (response->Status->StatusCode->StatusCode &&
					response->Status->StatusCode->StatusCode->Value) {
				status_value = response->Status->StatusCode->StatusCode->Value;
				if (strcmp(status_value,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST) == 0) {
					return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
				}
				if (strcmp(status_value,
						LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL) == 0) {
					return LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL;
				}
			}
		}
		return LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS;
	}

	if (response->Assertion) {
		LassoProfile *profile = LASSO_PROFILE(login);
		LassoSamlAssertion *assertion = response->Assertion->data;
		LassoLibAssertion *lib_assertion = NULL;

		if (LASSO_IS_LIB_ASSERTION(assertion)) {
			lib_assertion = LASSO_LIB_ASSERTION(assertion);
		}

		idp = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (idp == NULL) {
			return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
		}

		/* Validate AuthnRequest RequestID and InResponseTo */
		{
			char *previous_reqid = login->private_data->request_id;
			if (previous_reqid) {
				if (lib_assertion == NULL ||
					lib_assertion->InResponseTo == NULL ||
					strcmp(lib_assertion->InResponseTo, previous_reqid) != 0) {
					return critical_error(LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID);
				}
			}
		}

		/* If the status of the signature verification process is not 0, we try to verify on
		 * the assertion */
		if (profile->signature_status != 0) {
			xmlNode *assertion_xmlnode;
			gchar *assertion_issuer;

			assertion_xmlnode = lasso_node_get_original_xmlnode(LASSO_NODE(assertion));
			assertion_issuer = (gchar*)xmlGetProp(assertion_xmlnode, (xmlChar*)"Issuer");
			goto_cleanup_if_fail_with_rc(assertion_issuer, LASSO_PROFILE_ERROR_MISSING_ISSUER);
			goto_cleanup_if_fail_with_rc(strcmp(assertion_issuer, profile->remote_providerID) == 0,
					LASSO_PROFILE_ERROR_INVALID_ISSUER);

			if (assertion_xmlnode) {
				profile->signature_status = lasso_provider_verify_saml_signature(idp, assertion_xmlnode, NULL);
				goto_cleanup_if_fail_with_rc(profile->signature_status == 0, profile->signature_status);
			}
		}

		lasso_release_gobject(profile->nameIdentifier);

		/* Retrieve the name identifier from one of the statements */
		if (assertion->AuthenticationStatement) {
			sssa = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
					assertion->AuthenticationStatement);
			if (sssa->Subject && sssa->Subject->NameIdentifier) {
				lasso_assign_gobject(profile->nameIdentifier,
						LASSO_NODE(sssa->Subject->NameIdentifier));
			}
		}

		if (profile->nameIdentifier == NULL && assertion->AttributeStatement) {
			sas = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AttributeStatement);
			if (sas->Subject && sas->Subject->NameIdentifier) {
				lasso_assign_gobject(profile->nameIdentifier,
						LASSO_NODE(sas->Subject->NameIdentifier));
			}
		}

		if (profile->nameIdentifier == NULL) {
			return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
		}

	}
cleanup:

	return rc;
}

/*****************************************************************************/
/* public methods */
/*****************************************************************************/

/**
 * lasso_login_accept_sso:
 * @login: a #LassoLogin
 *
 * Gets the assertion of the response and adds it to the #LassoSession object.
 * Builds a federation with the 2 name identifiers of the assertion
 * and adds it into the identity.
 * If the session or the identity are NULL, they are created.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>
 * #LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_MISSING_RESPONSE if no response is present in the login profile object;
 * usually because no call to lasso_login_process_authn_response_msg was done;
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_MISSING_ASSERTION if the response does not contain an assertion,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND if the assertion does not contain a NameID element,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER same as
 * #LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_LOGIN_ERROR_ASSERTION_REPLAY if the assertion has already been used.
 * </para></listitem>
 * </itemizedlist>
 **/
gint
lasso_login_accept_sso(LassoLogin *login)
{
	LassoProfile *profile;
	LassoSamlAssertion *assertion;
	LassoSamlNameIdentifier *ni, *idp_ni = NULL;
	LassoFederation *federation;
	LassoSamlSubjectStatementAbstract *authentication_statement;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	if (profile->identity == NULL)
		profile->identity = lasso_identity_new();

	if (profile->session == NULL)
		profile->session = lasso_session_new();

	if (profile->response == NULL)
		return LASSO_PROFILE_ERROR_MISSING_RESPONSE;

	IF_SAML2(profile) {
		return lasso_saml20_login_accept_sso(login);
	}

	if (LASSO_SAMLP_RESPONSE(profile->response)->Assertion == NULL)
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;

	assertion = LASSO_SAMLP_RESPONSE(profile->response)->Assertion->data;
	if (assertion == NULL)
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;

	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_NODE(assertion));

	authentication_statement = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
			assertion->AuthenticationStatement);
	if (authentication_statement->Subject == NULL)
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;

	ni = authentication_statement->Subject->NameIdentifier;

	if (ni == NULL)
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;

	if (LASSO_IS_LIB_SUBJECT(authentication_statement->Subject)) {
		idp_ni = LASSO_LIB_SUBJECT(
				authentication_statement->Subject)->IDPProvidedNameIdentifier;
	}

	/* create federation, only if nameidentifier format is Federated */
	if (ni->Format && strcmp(ni->Format, LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED) == 0) {
		federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);
		if (ni != NULL && idp_ni != NULL) {
			federation->local_nameIdentifier = g_object_ref(ni);
			federation->remote_nameIdentifier = g_object_ref(idp_ni);
		} else {
			federation->remote_nameIdentifier = g_object_ref(ni);
		}
		/* add federation in identity */
		lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
	}

	return 0;
}

static void
lasso_login_build_assertion_artifact(LassoLogin *login)
{
	xmlSecByte samlArt[42], *b64_samlArt;
	char *identityProviderSuccinctID;

	identityProviderSuccinctID = lasso_sha1(
			LASSO_PROVIDER(LASSO_PROFILE(login)->server)->ProviderID);

	/* Artifact Format is described in "Binding Profiles", 3.2.2.2. */
	memcpy(samlArt, "\000\003", 2); /* type code */
	memcpy(samlArt+2, identityProviderSuccinctID, 20);
	lasso_build_random_sequence((char*)samlArt+22, 20);

	xmlFree(identityProviderSuccinctID);
	b64_samlArt = xmlSecBase64Encode(samlArt, 42, 0);

	lasso_assign_string(login->assertionArtifact, (char*)b64_samlArt);
	lasso_assign_string(login->parent.private_data->artifact,
			(char*)b64_samlArt);
	lasso_release_xml_string(b64_samlArt);
}

/**
 * lasso_login_build_artifact_msg:
 * @login: a #LassoLogin
 * @http_method: the HTTP method to send the artifact (REDIRECT or POST)
 *
 * Builds a SAML artifact. Depending of the HTTP method, the data for the sending of
 * the artifact are stored in @msg_url (REDIRECT) or @msg_url, @msg_body and
 * @msg_relayState (POST).
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID if no remote provider ID was setup in the login
 * profile object, it's usually done by lasso_login_process_authn_request_msg,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD if the HTTP method is neither LASSO_HTTP_METHOD_REDIRECT
 * or LASSO_HTTP_METHOD_POST (ID-FF 1.2 case) or neither LASSO_HTTP_METHOD_ARTIFACT_GET or
 * LASSO_HTTP_METHOD_ARTIFACT_POST (SAML 2.0 case) for SAML 2.0),
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE if the current protocolProfile is not
 * </para></listitem>
 * <listitem><para>
 * LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART (only for ID-FF 1.2),
 * </para></listitem>
 * <listitem><para>
 * LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the remote provider is not known to our server object
 * which impeach us to find a service endpoint,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_MISSING_RESPONSE if the response object is missing,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_MISSING_STATUS_CODE if the response object is missing a status code,
 * </para></listitem>
 *</itemizedlist>
 *
 **/
gint
lasso_login_build_artifact_msg(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProvider *remote_provider = NULL;
	LassoProfile *profile = NULL;
	gchar *url = NULL;
	xmlChar *b64_samlArt = NULL;
	xmlChar *relayState = NULL;
	gint rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);
	lasso_profile_clean_msg_info(profile);

	if (profile->remote_providerID == NULL) {
		/* this means lasso_login_init_request was not called before */
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	IF_SAML2(profile) {
		return lasso_saml20_login_build_artifact_msg(login, http_method);
	}

	if (http_method != LASSO_HTTP_METHOD_REDIRECT && http_method != LASSO_HTTP_METHOD_POST) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	/* ProtocolProfile must be BrwsArt */
	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	/* build artifact infos */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		goto_cleanup_with_rc(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	url = lasso_provider_get_assertion_consumer_service_url(remote_provider,
			LASSO_LIB_AUTHN_REQUEST(profile->request)->AssertionConsumerServiceID);
	if (url == NULL) {
		/* from draft-liberty-idff-protocols-schema-1.2-errata-v2.0.pdf
		 * paragraph starting line 768,
		 *
		 * If the <AssertionConsumerServiceID> element is provided,
		 * then the identity provider MUST search for the value among
		 * the id attributes in the <AssertionConsumerServiceURL>
		 * elements in the provider's metadata to determine the URL
		 * to use. If no match can be found, then the provider MUST
		 * return an error with a second-level <samlp:StatusCode> of
		 * lib:InvalidAssertionConsumerServiceIndex to the default URL
		 */
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_INVALID_ASSERTION_CONSUMER_SERVICE_INDEX);
		url = lasso_provider_get_assertion_consumer_service_url(
				remote_provider, NULL);
	}

	/* it may have been created in lasso_login_build_assertion */
	if (login->assertionArtifact == NULL)
		lasso_login_build_assertion_artifact(login);

	if (login->assertion) {
		LassoSamlAssertion *assertion = login->assertion;
		LassoSamlSubjectStatementAbstract *ss;

		ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement);
		/* Subject and SubjectConfirmation should never be NULL
		 * because they're built by Lasso
		 */
		if (ss->Subject != NULL && ss->Subject->SubjectConfirmation != NULL) {
			if (assertion->MajorVersion == 1 && assertion->MinorVersion == 0) {
				lasso_list_add_string(ss->Subject->SubjectConfirmation->ConfirmationMethod,
					LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01);
			} else {
				lasso_list_add_string(ss->Subject->SubjectConfirmation->ConfirmationMethod,
						LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT);
			}
		}
	}

	b64_samlArt = xmlStrdup((xmlChar*)login->assertionArtifact);
	relayState = xmlURIEscapeStr(
			(xmlChar*)LASSO_LIB_AUTHN_REQUEST(profile->request)->RelayState, NULL);

	if (http_method == LASSO_HTTP_METHOD_REDIRECT) {
		xmlChar *escaped_artifact = xmlURIEscapeStr(b64_samlArt, NULL);
		gchar *query = NULL;

		if (relayState == NULL) {
			query = g_strdup_printf("SAMLart=%s", escaped_artifact);
		} else {
			query = g_strdup_printf("SAMLart=%s&RelayState=%s",
					escaped_artifact, relayState);
		}
		lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
		lasso_release_string(query);
		lasso_release_xml_string(escaped_artifact);
	}

	if (http_method == LASSO_HTTP_METHOD_POST) {
		lasso_assign_string(profile->msg_url, url);
		lasso_assign_string(profile->msg_body, (char*)b64_samlArt);
		if (relayState != NULL) {
			lasso_assign_string(profile->msg_relayState, (char*)relayState);
		}
	}

	if (strcmp(LASSO_SAMLP_RESPONSE(profile->response)->Status->StatusCode->Value,
				LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		if (profile->session == NULL)
			profile->session = lasso_session_new();

		lasso_session_add_status(profile->session, profile->remote_providerID,
				g_object_ref(LASSO_SAMLP_RESPONSE(profile->response)->Status));
	} else {
		lasso_session_remove_status(profile->session, profile->remote_providerID);
	}

	/* store the response as the artifact message */
	lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(
				profile->server,
				profile->remote_providerID,
				profile->response));
	/* comply with the new way of storing artifacts */
	lasso_assign_string(profile->private_data->artifact,
			login->assertionArtifact);
	/* Artifact profile for ID-FF 1.2 is special, this is not the full message which is relayed
	 * but only its assertion content, the Response container is changed from a
	 * lib:AuthnResponse to a samlp:Response.
	 */
	lasso_assign_new_string(profile->private_data->artifact_message,
			lasso_node_export_to_xml((LassoNode*)login->assertion));
cleanup:
	lasso_release_string(url);
	lasso_release_xml_string(b64_samlArt);
	lasso_release_xml_string(relayState);
	return rc;
}

/**
 * lasso_login_build_authn_request_msg:
 * @login: a #LassoLogin
 *
 * Converts profile authentication request (@request member) into a Liberty message, either an URL
 * in HTTP-Redirect profile or an URL and a field value in Browser-POST (form) profile.
 *
 * The URL is set into the @msg_url member and the eventual field value (LAREQ) is set into the
 * @msg_body member.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>
 * #LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID if not remote provider ID was setup&160;- it usually
 * means that lasso_login_init_request() was not called before,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the remote provider ID is not registered in the server
 * object,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE if the SSO profile is not supported by the targeted
 * provider,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED if the building of the query part of the redirect URL
 * or of the body of the POST content failed&160;- it only happens with the #LASSO_HTTP_METHOD_REDIRECT,
 * #LASSO_HTTP_METHOD_POST, #LASSO_HTTP_METHOD_ARTIFACT_GET and
 * #LASSO_HTTP_METHOD_ARTIFACT_POST bindings&160;-,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL if the metadata of the remote provider does not contain
 * an url for the SSO profile,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_INVALID_REQUEST if the request object is not of the needed type, is usually
 * means that lasso_login_init_request() was not called before,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_MISSING_REQUEST if the request object is missing,
 * </para></listitem>
 * <listitem><para>
 * #LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD if the current setted @http_method on the #LassoLogin
 * object is invalid.
 * </para></listitem>
 * </itemizedlist>
 **/
lasso_error_t
lasso_login_build_authn_request_msg(LassoLogin *login)
{
	LassoProvider *provider, *remote_provider;
	LassoProfile *profile;
	char *md_authnRequestsSigned, *url, *query = NULL, *lareq, *protocolProfile;
	LassoProviderRole role, remote_role;
	gboolean must_sign;
	gint rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	profile = LASSO_PROFILE(login);
	lasso_profile_clean_msg_info(profile);

	if (profile->remote_providerID == NULL) {
		/* this means lasso_login_init_request was not called before */
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	provider = LASSO_PROVIDER(profile->server);
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	IF_SAML2(profile) {
		return lasso_saml20_login_build_authn_request_msg(login);
	}

	protocolProfile = LASSO_LIB_AUTHN_REQUEST(profile->request)->ProtocolProfile;
	if (protocolProfile == NULL)
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;

	role = provider->role;
	provider->role = LASSO_PROVIDER_ROLE_SP; /* we act as an SP for sure here */
	remote_role = remote_provider->role;
	remote_provider->role = LASSO_PROVIDER_ROLE_IDP; /* and remote is IdP */

	if (lasso_provider_has_protocol_profile(remote_provider,
				LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON, protocolProfile) == FALSE) {
		provider->role = role;
		remote_provider->role = remote_role;
		return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
	}

	/* check if authnRequest must be signed */
	md_authnRequestsSigned = lasso_provider_get_metadata_one(provider, "AuthnRequestsSigned");
	must_sign = (md_authnRequestsSigned && strcmp(md_authnRequestsSigned, "true") == 0);
	lasso_release_string(md_authnRequestsSigned);

	/* restore original roles */
	provider->role = role;
	remote_provider->role = remote_role;

	if (login->http_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* REDIRECT -> query */
		if (must_sign) {
			lasso_check_good_rc(lasso_server_export_to_query_for_provider_by_name(profile->server,
						profile->remote_providerID,
						profile->request, &query));
		} else {
			query = lasso_node_build_query(LASSO_NODE(profile->request));
		}
		if (query == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}

		/* get SingleSignOnServiceURL metadata */
		url = lasso_provider_get_metadata_one(remote_provider, "SingleSignOnServiceURL");
		if (url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}

		lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
		lasso_release_string(profile->msg_body);
		lasso_release_string(query);
		lasso_release_string(url);
	}
	if (login->http_method == LASSO_HTTP_METHOD_POST) {
		if (must_sign) {
			lasso_server_set_signature_for_provider_by_name(profile->server,
					profile->remote_providerID,
					profile->request);
		}
		lareq = lasso_node_export_to_base64(profile->request);

		if (lareq == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}

		lasso_assign_new_string(profile->msg_url, lasso_provider_get_metadata_one(
				remote_provider, "SingleSignOnServiceURL"));
		lasso_assign_new_string(profile->msg_body, lareq);
	}

cleanup:
	return rc;
}

/**
 * lasso_login_build_authn_response_msg:
 * @login: a #LassoLogin
 *
 * Converts profile authentication response (@response member) into a Liberty
 * message.
 *
 * The URL is set into the @msg_url member and the field value (LARES) is set
 * into the @msg_body member.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE if the current protocol profile is not
 * </para></listitem>
 * <listitem><para>
 * LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST or LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP,
 * </para></listitem>
 * <listitem><para>
 * LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the remote provider ID is not registered in the server
 * object,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL if the metadata of the remote provider does not contain
 * an URL for the assertion consuming service,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_MISSING_SERVER the server object is needed to sign a message and it is
 * missing,
 * </para></listitem>
 * <listitem><para>
 * LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED the private key for signing could not be found,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_MISSING_RESPONSE if the response object is missing,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE if the SSO profile is not supported by the targeted
 * provider,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_BUILDING_QUERY_FAILED if using #LASSO_HTTP_METHOD_REDIRECT building of the redirect
 * URL failed,
 * </para></listitem>
 * <listitem><para>
 * LASSO_PROFILE_BUILDING_MSG_FAILED if using #LASSO_HTTP_METHOD_POST, #LASSO_HTTP_METHOD_SOAP or
 * #LASSO_HTTP_METHOD_PAOS and building the @msg_body failed.
 * </para></listitem>
 * </itemizedlist>
 *
 **/
gint
lasso_login_build_authn_response_msg(LassoLogin *login)
{
	LassoProvider *remote_provider = NULL;
	LassoProfile *profile = NULL;
	lasso_error_t rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);
	lasso_profile_clean_msg_info(profile);

	IF_SAML2(profile) {
		return lasso_saml20_login_build_authn_response_msg(login);
	}

	/* ProtocolProfile must be BrwsPost */
	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST &&
			login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	if (login->assertion) {
		LassoSamlAssertion *assertion = login->assertion;
		LassoSamlSubjectStatementAbstract *ss;
		ss = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement);
		if (ss->Subject && ss->Subject->SubjectConfirmation) {
			lasso_list_add_string(ss->Subject->SubjectConfirmation->ConfirmationMethod,
					LASSO_SAML_CONFIRMATION_METHOD_BEARER);
		}
	}

	/* Countermeasure: The issuer should sign <lib:AuthnResponse> messages.
	 * (binding and profiles (1.2errata2, page 65) */
	lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(
				profile->server,
				profile->remote_providerID,
				profile->response));

	/* build an lib:AuthnResponse base64 encoded */
	lasso_assign_new_string(profile->msg_body,
			lasso_node_export_to_base64(LASSO_NODE(profile->response)));

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	lasso_assign_new_string(profile->msg_url, lasso_provider_get_assertion_consumer_service_url(remote_provider,
			LASSO_LIB_AUTHN_REQUEST(profile->request)->AssertionConsumerServiceID));
	if (profile->msg_url == NULL) {
		return LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL;
	}
cleanup:
	return rc;
}

/**
 * lasso_login_build_request_msg:
 * @login: a #LassoLogin
 *
 * Produce a SOAP Artifact Resolve message. It must follows a call to
 * lasso_login_init_request() on the artifact message.
 * Converts  artifact request into a Liberty SOAP message.
 *
 * The URL is set into the @msg_url member and the SOAP message is set into the
 * @msg_body member. You should POST the @msg_body to the @msg_url afterward.
 *
 * Return value: 0 on success; or
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID if not remote provider ID was setup -- it usually
 * means that lasso_login_init_request was not called before,
 * LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the remote provider ID is not registered in the server
 * object.
 *
 **/
gint
lasso_login_build_request_msg(LassoLogin *login)
{
	LassoProvider *remote_provider;
	LassoProfile *profile;
	lasso_error_t rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);
	lasso_profile_clean_msg_info(profile);

	IF_SAML2(profile) {
		return lasso_saml20_login_build_request_msg(login);
	}

	if (profile->remote_providerID == NULL) {
		/* this means lasso_login_init_request was not called before */
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(
				profile->server,
				profile->remote_providerID,
				profile->request));
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(profile->request));

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}
	lasso_assign_new_string(profile->msg_url, lasso_provider_get_metadata_one(remote_provider, "SoapEndpoint"));
cleanup:
	return rc;
}

/**
 * lasso_login_build_response_msg:
 * @login: a #LassoLogin
 * @remote_providerID: service provider ID
 *
 * Converts profile assertion response (@response member) into a Liberty SOAP
 * messageresponse message.
 *
 * The URL is set into the @msg_url member and the SOAP message is set into the
 * @msg_body member.
 *
 * Return value: 0 on success; or a negative value otherwise.
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * LASSO_PROFILE_ERROR_SESSION_NOT_FOUND if no session object was found in the login profile object
 * -- it should be created by lasso_login_build_assertion() if you did not set it manually before
 *  calling lasso_login_build_assertion().
 *
 **/
gint
lasso_login_build_response_msg(LassoLogin *login, gchar *remote_providerID)
{
	LassoProvider *remote_provider = NULL;
	LassoProfile *profile = NULL;
	lasso_error_t rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	profile = LASSO_PROFILE(login);
	lasso_profile_clean_msg_info(profile);

	IF_SAML2(profile) {
		return lasso_saml20_login_build_response_msg(login);
	}

	lasso_assign_new_gobject(profile->response, lasso_samlp_response_new());
	lasso_assign_string(LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->InResponseTo,
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->RequestID);
	if (LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MajorVersion == 1 &&
			LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MinorVersion == 0) {
		/* this is a SAML 1.0 request, must create SAML 1.0 response */
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->MinorVersion = 0;
	}

	if (remote_providerID != NULL) {
		lasso_assign_string(profile->remote_providerID, remote_providerID);
		remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		rc = lasso_provider_verify_signature(remote_provider,
				login->private_data->soap_request_msg,
				"RequestID", LASSO_MESSAGE_FORMAT_SOAP);
		lasso_release_string(login->private_data->soap_request_msg);

		/* lasso_profile_set_session_from_dump has not been called */
		if (profile->session == NULL) {
			rc = LASSO_PROFILE_ERROR_SESSION_NOT_FOUND;
		}

		/* change status code into RequestDenied if signature is
		 * invalid or not found or if an error occurs during
		 * verification */
		if (rc != 0) {
			lasso_profile_set_response_status(profile,
					LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		}

		if (rc == 0) {
			/* get assertion in session and add it in response */
			LassoSamlAssertion *assertion;
			LassoSamlpStatus *status;

			status = LASSO_SAMLP_STATUS(lasso_session_get_status(
						profile->session, remote_providerID));
			assertion = LASSO_SAML_ASSERTION(
					lasso_session_get_assertion(profile->session,
						profile->remote_providerID));
			if (status) {
				lasso_assign_gobject(LASSO_SAMLP_RESPONSE(profile->response)->Status,
					status);
				lasso_session_remove_status(profile->session,
						remote_providerID);
			} else if (assertion) {
				lasso_list_add_gobject(LASSO_SAMLP_RESPONSE(profile->response)->Assertion,
					assertion);
				lasso_profile_set_response_status(profile,
						LASSO_SAML_STATUS_CODE_SUCCESS);
				lasso_session_remove_status(profile->session, remote_providerID);
			} else if (profile->private_data->artifact_message) {
				xmlDoc *doc;
				char *artifact_message = profile->private_data->artifact_message;
				doc = lasso_xml_parse_memory(artifact_message,
						strlen(artifact_message));
				lasso_profile_set_response_status(profile,
						LASSO_SAML_STATUS_CODE_SUCCESS);
				lasso_list_add_new_gobject(((LassoSamlpResponse*)profile->response)->Assertion,
						lasso_misc_text_node_new_with_xml_node(xmlDocGetRootElement(doc)));
				lasso_release_doc(doc);
			}
		}
	} else {
		lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
	}

	lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(
				profile->server,
				profile->remote_providerID,
				profile->response));
	lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(profile->response));

cleanup:
	return rc;
}

/**
 * lasso_login_destroy:
 * @login: a #LassoLogin
 *
 * Destroys a #LassoLogin object.
 *
 * @Deprecated: Since #2.2.1, use g_object_unref() instead.
 **/
void
lasso_login_destroy(LassoLogin *login)
{
	lasso_release_gobject(login);
}

/**
 * lasso_login_init_authn_request:
 * @login: a #LassoLogin
 * @remote_providerID:(allow-none): the providerID of the identity provider (may be NULL)
 * @http_method:(default LASSO_HTTP_METHOD_REDIRECT): HTTP method to use for request transmission
 *
 * <para>Initializes a new AuthnRequest from current service provider to remote
 * identity provider specified in @remote_providerID (if NULL the first known
 * identity provider is used).</para>
 *
 * <para>For ID-FF 1.2 the default NameIDPolicy in an AuthnRequest is None, which imply that a
 * federation must already exist on the IdP side.</para>
 *
 * <para>For SAML 2.0 the default NameIDPolicy is the first listed in the metadatas of the current
 * provider, or if none is specified, Transient, which ask the IdP to give a one-time
 * federation</para>
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,</para></listitem>
 * <listitem><para>LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID if @remote_providerID is NULL and no default remote
 * provider could be found from the server object -- usually the first one in the order of adding to
 * the server object --,</para></listitem>
 * <listitem><para>LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the @remote_providerID is not known to our server object.</para></listitem>
 * <listitem><para>LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD if the HTTP method is neither LASSO_HTTP_METHOD_REDIRECT
 * or LASSO_HTTP_METHOD_POST,</para></listitem>
 * <listitem><para>LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED if creation of the request object failed.</para></listitem>
 * </itemizedlist>
 *
 **/
gint
lasso_login_init_authn_request(LassoLogin *login, const gchar *remote_providerID,
		LassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoServer *server = NULL;
	LassoSamlpRequestAbstract *request;
	lasso_error_t rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);
	lasso_extract_node_or_fail(server, profile->server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);

	/* clean state */
	lasso_release_string (profile->remote_providerID);
	lasso_release_gobject (profile->request);

	if (remote_providerID != NULL) {
		lasso_assign_string(profile->remote_providerID, remote_providerID);
	} else {
		lasso_assign_new_string(profile->remote_providerID, lasso_server_get_first_providerID_by_role(profile->server, LASSO_PROVIDER_ROLE_IDP));
		if (profile->remote_providerID == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
		}
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	remote_provider->role = LASSO_PROVIDER_ROLE_IDP;
	server->parent.role = LASSO_PROVIDER_ROLE_SP;

	IF_SAML2(profile) {
		return lasso_saml20_login_init_authn_request(login, http_method);
	}

	if (http_method != LASSO_HTTP_METHOD_REDIRECT && http_method != LASSO_HTTP_METHOD_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	login->http_method = http_method;

	lasso_assign_new_gobject(profile->request, LASSO_NODE(lasso_lib_authn_request_new()));
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	request = LASSO_SAMLP_REQUEST_ABSTRACT(profile->request);
	request->RequestID = lasso_build_unique_id(32);
	lasso_assign_string(login->private_data->request_id, request->RequestID);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	if (lasso_provider_get_protocol_conformance(remote_provider) < LASSO_PROTOCOL_LIBERTY_1_2) {
		request->MajorVersion = 1;
		request->MinorVersion = 0;
	}
	lasso_assign_new_string(request->IssueInstant, lasso_get_current_time());
	lasso_assign_string(LASSO_LIB_AUTHN_REQUEST(profile->request)->ProviderID,
			LASSO_PROVIDER(profile->server)->ProviderID);
	lasso_assign_string(LASSO_LIB_AUTHN_REQUEST(profile->request)->RelayState,
			profile->msg_relayState);

cleanup:

	return rc;
}


/**
 * lasso_login_init_request:
 * @login: a #LassoLogin
 * @response_msg: the authentication response received
 * @response_http_method: the method used to receive the authentication
 *      response
 *
 * Initializes an artifact request. @response_msg is either the query string
 * (in redirect mode) or the form LAREQ field (in browser-post mode).
 * It should only be used if you received an artifact message, @response_msg must be content of the
 * artifact field for the POST artifact binding of the query string for the REDIRECT artifact
 * binding. You must set the @response_http_method argument according to the way you received the
 * artifact message.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem>
 * <para>
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * LASSO_PARAM_ERROR_INVALID_VALUE if @response_msg is NULL,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD if the HTTP method is neither LASSO_HTTP_METHOD_REDIRECT
 * or LASSO_HTTP_METHOD_POST (in the ID-FF 1.2 case) or neither LASSO_HTTP_METHOD_ARTIFACT_GET or
 * LASSO_HTTP_METHOD_ARTIFACT_POST (in the SAML 2.0 case),
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * LASSO_PROFILE_ERROR_MISSING_ARTIFACT if no artifact field was found in the query string (only
 * possible for the LASSO_HTTP_METHOD_REDIRECT case),
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * LASSO_PROFILE_ERROR_INVALID_ARTIFACT if decoding of the artifact failed -- whether because
 * the base64 encoding is invalid or because the type code is wrong --,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID if no provider ID could be found corresponding to
 * the hash contained in the artifact.
 * </para>
 * </listitem>
 * </itemizedlist>
 *
 **/
gint
lasso_login_init_request(LassoLogin *login, gchar *response_msg,
		LassoHttpMethod response_http_method)
{
	char **query_fields;
	gint ret = 0;
	int i;
	char *artifact_b64 = NULL, *provider_succinct_id_b64;
	char provider_succinct_id[21];
	char artifact[43];
	LassoSamlpRequestAbstract *request;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(login);
	IF_SAML2(profile) {
		return lasso_saml20_login_init_request(login, response_msg,
				response_http_method);
	}
	if (response_http_method != LASSO_HTTP_METHOD_REDIRECT &&
			response_http_method != LASSO_HTTP_METHOD_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	/* rebuild response (artifact) */
	if (response_http_method == LASSO_HTTP_METHOD_REDIRECT) {
		query_fields = urlencoded_to_strings(response_msg);
		for (i=0; query_fields[i]; i++) {
			if (strncmp(query_fields[i], "SAMLart=", 8) == 0) {
				lasso_assign_string(artifact_b64, query_fields[i]+8);
			}
			if (strncmp(query_fields[i], "RelayState=", 11) == 0) {
				lasso_assign_string(profile->msg_relayState, query_fields[i]+11);
			}
			xmlFree(query_fields[i]);
		}
		lasso_release_string(query_fields);
		if (artifact_b64 == NULL) {
			return LASSO_PROFILE_ERROR_MISSING_ARTIFACT;
		}
	}
	if (response_http_method == LASSO_HTTP_METHOD_POST) {
		lasso_assign_string(artifact_b64, response_msg);
	}

	i = xmlSecBase64Decode((xmlChar*)artifact_b64, (xmlChar*)artifact, 43);
	if (i < 0 || i > 42) {
		lasso_release_string(artifact_b64);
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}

	if (artifact[0] != 0 || artifact[1] != 3) { /* wrong type code */
		lasso_release_string(artifact_b64);
		return LASSO_PROFILE_ERROR_INVALID_ARTIFACT;
	}

	memcpy(provider_succinct_id, artifact+2, 20);
	provider_succinct_id[20] = 0;

	provider_succinct_id_b64 = (char*)xmlSecBase64Encode((xmlChar*)provider_succinct_id, 20, 0);

	lasso_assign_new_string(profile->remote_providerID, lasso_server_get_providerID_from_hash(
			profile->server, provider_succinct_id_b64));
	xmlFree(provider_succinct_id_b64);
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	request = LASSO_SAMLP_REQUEST_ABSTRACT(lasso_samlp_request_new());
	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_SAML_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_SAML_MINOR_VERSION_N;
	lasso_assign_new_string(request->IssueInstant, lasso_get_current_time());
	LASSO_SAMLP_REQUEST(request)->AssertionArtifact = artifact_b64;
	lasso_assign_new_gobject(profile->request, LASSO_NODE(request));

	return ret;
}

/**
 * lasso_login_init_idp_initiated_authn_request:
 * @login: a #LassoLogin.
 * @remote_providerID: the providerID of the remote service provider (may be
 *      NULL)
 *
 * <para>Generates an authentication response without matching authentication
 * request.</para>
 *
 * <para>The choice of NameIDFormat is the same as for lasso_login_init_authn_request() but with the
 * target @remote_providerID as the current provider</para>
 *
 * <para>If @remote_providerID is NULL, the first known provider is used.</para>
 *
 * Return value: 0 on success; or a negative value otherwise. Error codes are the same as
 * lasso_login_init_authn_request().
 **/
gint
lasso_login_init_idp_initiated_authn_request(LassoLogin *login,
		const gchar *remote_providerID)
{
	int rc = 0;
	LassoProfile *profile;

	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_init_idp_initiated_authn_request(login,
				remote_providerID);
	}

	rc = lasso_login_init_authn_request(login, remote_providerID, LASSO_HTTP_METHOD_POST);
	if (rc)
		return rc;

	/* no RequestID attribute or it would be used in response assertion */
	lasso_release_string(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->RequestID);
	lasso_assign_string(LASSO_LIB_AUTHN_REQUEST(profile->request)->NameIDPolicy,
			LASSO_LIB_NAMEID_POLICY_TYPE_ANY);

	return 0;
}

/**
 * lasso_login_must_ask_for_consent:
 * @login: a #LassoLogin
 *
 * Evaluates if consent must be asked to the Principal to federate him.
 *
 * Return value: %TRUE if consent must be asked
 **/
gboolean
lasso_login_must_ask_for_consent(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_must_ask_for_consent(login);
	}

	if (LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->IsPassive) {
		return FALSE;
	}

	return lasso_login_must_ask_for_consent_private(login);
}


/**
 * lasso_login_must_authenticate:
 * @login: a #LassoLogin
 *
 * Evaluates if user must be authenticated.
 *
 * Return value: %TRUE if user must be authenticated
 **/
gboolean
lasso_login_must_authenticate(LassoLogin *login)
{
	LassoLibAuthnRequest *request;
	LassoProfile *profile;
	gboolean matched = TRUE;
	GList *assertions = NULL;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_must_authenticate(login);
	}

	request = LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request);
	if (request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
	}

	if (request->ForceAuthn == TRUE && request->IsPassive == FALSE)
		return TRUE;

	assertions = lasso_session_get_assertions(profile->session, NULL);
	if (request->RequestAuthnContext) {
		char *comparison = request->RequestAuthnContext->AuthnContextComparison;
		char *class_ref;
		GList *class_refs = request->RequestAuthnContext->AuthnContextClassRef;
		GList *t1, *t2;
		int compa = -1;

		if (comparison == NULL || strcmp(comparison, "exact") == 0) {
			compa = 0;
		} else if (strcmp(comparison, "minimum") == 0) {
			message(G_LOG_LEVEL_CRITICAL, "'minimum' comparison is not implemented");
			compa = 1;
		} else if (strcmp(comparison, "better") == 0) {
			message(G_LOG_LEVEL_CRITICAL, "'better' comparison is not implemented");
			compa = 2;
		}

		if (class_refs) {
			matched = FALSE;
		}

		for (t1 = class_refs; t1 && !matched; t1 = g_list_next(t1)) {
			class_ref = t1->data;
			for (t2 = assertions; t2 && !matched; t2 = g_list_next(t2)) {
				LassoSamlAssertion *assertion;
				LassoSamlAuthenticationStatement *as;
				char *method;

				if (LASSO_IS_SAML_ASSERTION(t2->data) == FALSE) {
					continue;
				}

				assertion = t2->data;

				as = LASSO_SAML_AUTHENTICATION_STATEMENT(
						assertion->AuthenticationStatement);
				method = as->AuthenticationMethod;

				if (strcmp(method, LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD) == 0)
				{
					/* mapping between SAML authentication
					 * methods and Liberty authentication
					 * context is not possible (excepted on
					 * that one)
					 */
					method = LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD;
				}

				switch (compa) {
				case 1: /* minimum */
					/* XXX: implement 'minimum' comparison */
				case 2: /* better */
					/* XXX: implement 'better' comparison */
				case 0: /* exact */
					if (strcmp(method, class_ref) == 0) {
						matched = TRUE;
					}
					break;
				default: /* inever reached */
					break;
				}
				if (matched == TRUE) {
					break;
				}
			}
		}

	} else {
		/* if nothing specific was asked; don't look for any
		 * particular assertions, one is enough
		 */
		matched = (profile->session != NULL && \
				lasso_session_count_assertions(profile->session) > 0);
	}
	lasso_release_list(assertions);

	if (matched == FALSE && request->IsPassive == FALSE)
		return TRUE;

	if (LASSO_PROFILE(login)->identity == NULL && request->IsPassive &&
			login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST) {
		lasso_profile_set_response_status(LASSO_PROFILE(login),
				LASSO_LIB_STATUS_CODE_NO_PASSIVE);
		return FALSE;
	}

	return FALSE;
}

/**
 * lasso_login_process_authn_request_msg:
 * @login: a #LassoLogin
 * @authn_request_msg: the authentication request received
 *
 * Processes received authentication request, checks it is signed correctly,
 * checks if requested protocol profile is supported, etc.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem>
 * <para>
 * #LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is no a #LassoLogin object,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * #LASSO_PROFILE_ERROR_MISSING_REQUEST if @authn_request_msg is #NULL and no request as actually
 * been processed or initialized &#151; see lasso_login_init_idp_initiated_authn_request(),
 *
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * #LASSO_PROFILE_ERROR_INVALID_MSG if the content of @authn_request_msg cannot be parsed to as a
 * valid lib:AuthnRequest messages for any support binding (mainly HTTP-Redirect, HTTP-Post and
 * SOAP),
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_PROFILE_ERROR_MISSING_ISSUER if the parsed samlp2:AuthnRequest does not have a proper Issuer element,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_PROFILE_ERROR_INVALID_REQUEST if the parsed message does not validate as a valid
 * samlp2:AuthnRequest (SAMLv2) i.e. if there is no Issuer, or mutually exclusive attributes are
 * used (ProtocolBinding and AssertionConsumerServiceIndex),
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE if the protocolProfile (ID-FFv1.2) or the
 * protocolBinding (SAMLv2) is unsupported by Lasso,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE if the protocolProfile (ID-FFv1.2) or the protocolBinding
 * (SAMLv2) for the AssertionConsumer is unsupported by this provider implementation as indicated by
 * its metadata file,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER, or
 * #LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the metadata for the issuer of the request are absent
 * from the #LassoServer object of this profile,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_DS_ERROR_SIGNATURE_NOT_FOUND if no signature could be found and signature validation is
 * forced &#151; by the service provider metadata with the AuthnRequestsSigned attribute
 * (ID-FFv1.2&SAMLv2), the attribute WantAuthnRequestsSigned in the identity provider metadata file
 * (SAMLv2) or as advised by the lasso_profile_set_signature_verify_hint() method),
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 *
 * #LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED if the signature validation failed on a present
 * signature,
 * </para>
 * </listitem>
 * <listitem>
 * <para>
 * #LASSO_DS_ERROR_INVALID_SIGNATURE if the signature was malformed and a signature was present,
 * </para>
 * </listitem>
 * </itemizedlist>
 *
 **/
gint
lasso_login_process_authn_request_msg(LassoLogin *login, const char *authn_request_msg)
{
	LassoProvider *remote_provider;
	gchar *protocolProfile;
	gchar *authnRequestSigned;
	gboolean must_verify_signature = FALSE;
	gint ret = 0;
	LassoLibAuthnRequest *request;
	LassoMessageFormat format;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_process_authn_request_msg(login, authn_request_msg);
	}

	if (authn_request_msg == NULL) {
		format = 0;
		if (profile->request == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
		}

		/* LibAuthnRequest already set by lasso_login_init_idp_initiated_authn_request() */
		request = LASSO_LIB_AUTHN_REQUEST(profile->request);
	} else {
		request = lasso_lib_authn_request_new();
		format = lasso_node_init_from_message(LASSO_NODE(request), authn_request_msg);
		if (format == LASSO_MESSAGE_FORMAT_UNKNOWN ||
				format == LASSO_MESSAGE_FORMAT_ERROR) {
			return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
		}

		lasso_assign_new_gobject(profile->request, request);
		if (! LASSO_IS_LIB_AUTHN_REQUEST(profile->request)) {
			lasso_release_gobject(profile->request);
			return LASSO_PROFILE_ERROR_INVALID_MSG;
		}

		/* get remote ProviderID */
		lasso_assign_string(profile->remote_providerID,
				LASSO_LIB_AUTHN_REQUEST(profile->request)->ProviderID);

		/* get RelayState */
		lasso_assign_string(profile->msg_relayState, request->RelayState);
	}


	/* get ProtocolProfile in lib:AuthnRequest */
	protocolProfile = LASSO_LIB_AUTHN_REQUEST(profile->request)->ProtocolProfile;
	if (protocolProfile == NULL ||
			strcmp(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART) == 0) {
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
	} else if (strcmp(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST) == 0) {
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST;
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
	} else if (strcmp(protocolProfile, LASSO_LIB_PROTOCOL_PROFILE_BRWS_LECP) == 0) {
		protocolProfile = LASSO_LIB_PROTOCOL_PROFILE_BRWS_LECP;
		login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
	} else {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	/* check if requested single sign on protocol profile is supported */
	LASSO_PROVIDER(profile->server)->role = LASSO_PROVIDER_ROLE_IDP;
	if (lasso_provider_has_protocol_profile(
				LASSO_PROVIDER(profile->server),
				LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON,
				protocolProfile) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
	}

	/* Check authnRequest signature. */
	if (authn_request_msg != NULL) {
		LassoProfileSignatureVerifyHint sig_verify_hint;

		sig_verify_hint = lasso_profile_get_signature_verify_hint(profile);
		remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (remote_provider == NULL) {
			return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
		}
		/* Is authnRequest signed ? */
		must_verify_signature = TRUE;
		authnRequestSigned = lasso_provider_get_metadata_one(
				remote_provider, "AuthnRequestsSigned");
		if (authnRequestSigned != NULL) {
			must_verify_signature = strcmp(authnRequestSigned, "true") == 0;
			lasso_release_string(authnRequestSigned);
		}
		if (sig_verify_hint == LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE) {
			must_verify_signature = TRUE;
		}
		if (sig_verify_hint == LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE) {
			must_verify_signature = FALSE;
		}
		/* reset the signature_status, and if signature validation was not really needed
		 * just choke on the presence of an invalid signature, if no signature just goes on
		 * */
		profile->signature_status = 0;
		if (must_verify_signature) {
			ret = lasso_provider_verify_signature(remote_provider,
					authn_request_msg, "RequestID", format);
			if (profile == LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE && ret !=
					LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
				profile->signature_status = ret;
			}
		}
	}

	/* create LibAuthnResponse */
	lasso_assign_new_gobject(profile->response, lasso_lib_authn_response_new(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_LIB_AUTHN_REQUEST(profile->request)));
	if (LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MajorVersion == 1 &&
			LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MinorVersion < 2) {
		/* pre-id-ff 1.2, move accordingly */
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->MajorVersion = 1;
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->MinorVersion = 0;
	}


	return ret;
}

/**
 * lasso_login_process_authn_response_msg:
 * @login: a #LassoLogin
 * @authn_response_msg: the authentication response received
 *
 * Processes received authentication response.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>#LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin
 * object,</para></listitem>
 * <listitem><para>#LASSO_PARAM_ERROR_INVALID_VALUE if authn_response_msg is NULL,</para></listitem>
 * <listitem><para>#LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND, if the issuing
 * provider of the assertion is not registered in the #LassoServer object,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_MISSING_ISSUER if the parsed samlp2:AuthnRequest does not
 * have a proper Issuer element, </para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_MISSING_STATUS_CODE if the reponse is missing a
 * <literal>StatusCode</literal> element,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_STATUS_NOT_SUCCESS_ERROR if the identity provider returned a
 * failure response,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_REQUEST_DENIED</para> if the identity provider returned the
 * specific status code <literal>RequestDenied</literal>,</listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_INVALID_MSG if the message is not a #LassoSamlpResponse
 * (ID-FF 1.2) or a #LassoSamlp2ResponseMsg (SAML 2.0),</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE, if the received message format does not
 * correspond to a binding supported by this function, the only supported binding by this function
 * is HTTP POST,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_MISSING_SERVER the server object is needed to sign a message
 * and it is missing,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE if the validation of the signature
 * of the message failed, a specific error code is available in
 * <literal>login->parent.signature_status</literal></para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID if the received response
 * does not match the saved AuthenticationRequest ID,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_INVALID_ISSUER if the assertion issuer does not match the
 * AuthenticationResponse issuer,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND if not NameID could be found or
 * decoded,</para></listitem>
 * </itemizedlist>
 **/
gint
lasso_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg)
{
	LassoMessageFormat format;
	LassoProvider *remote_provider;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(authn_response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_process_authn_response_msg(login, authn_response_msg);
	}

	/* clean state */
	lasso_release_string (profile->remote_providerID);
	lasso_release_gobject(profile->response);

	lasso_assign_new_gobject(profile->response, lasso_lib_authn_response_new(NULL, NULL));
	format = lasso_node_init_from_message(
			LASSO_NODE(profile->response), authn_response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	lasso_assign_string(profile->remote_providerID,
			LASSO_LIB_AUTHN_RESPONSE(profile->response)->ProviderID);

	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	lasso_assign_string(profile->msg_relayState, LASSO_LIB_AUTHN_RESPONSE(
			profile->response)->RelayState);

	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, authn_response_msg, "ResponseID", format);

	if (profile->signature_status) {
		return profile->signature_status;
	}
	return lasso_login_process_response_status_and_assertion(login);
}


/**
 * lasso_login_process_request_msg:
 * @login: a #LassoLogin
 * @request_msg: the artifact request received
 *
 * Processes received artifact request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_login_process_request_msg(LassoLogin *login, gchar *request_msg)
{
	gint ret = 0;
	LassoProfile *profile = LASSO_PROFILE(login);

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	IF_SAML2(profile) {
		return lasso_saml20_login_process_request_msg(login, request_msg);
	}

	/* rebuild samlp:Request with request_msg */
	lasso_assign_new_gobject(profile->request, lasso_node_new_from_soap(request_msg));
	if (profile->request == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	/* get AssertionArtifact */
	lasso_assign_string(login->assertionArtifact,
			LASSO_SAMLP_REQUEST(profile->request)->AssertionArtifact);
	lasso_assign_string(login->parent.private_data->artifact,
			login->assertionArtifact);

	/* Keep a copy of request msg so signature can be verified when we get
	 * the providerId in lasso_login_build_response_msg()
	 */
	lasso_assign_string(login->private_data->soap_request_msg, request_msg);

	return ret;
}


/**
 * lasso_login_process_response_msg:
 * @login: a #LassoLogin
 * @response_msg: the assertion response received
 *
 * Processes received assertion response.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>#LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,</para></listitem>
 * <listitem><para>#LASSO_PARAM_ERROR_INVALID_VALUE if response_msg is NULL,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_INVALID_MSG if the message is not a #LassoSamlpResponse (ID-FF 1.2) or a #LassoSamlp2ResponseMsg (SAML 2.0),</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_RESPONSE_DOES_NOT_MATCH_REQUEST if the response does not refer to the request or if the response refer to an unknown request and <link linkend="strict-checking"><literal>strict-checking</literal></link> is activated ,</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_REQUEST_DENIED the identity provided
 * returned a failure status of "RequestDenied"</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND if creation of a new
 * federation was not allowed and none existed,</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL if authentication failed
 * or/and if the user cancelled the authentication,</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS, if the response status
 * is a failure but we have no more precise error code to report it, you must
 * look at the second level status in the response,</para></listitem>
 * <listitem><para>#LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND, if the issuing
 * provider of the assertion is unknown,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_INVALID_ISSUER the issuer of the
 * assertion received, is not the expected one</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND no statement was fournd, or none statement contains a subject with a name identifier,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_MISSING_STATUS_CODE if the reponse is
 * missing a <literal>StatusCode</literal> element,</para></listitem>
 * <listitem><para>#LASSO_PROFILE_ERROR_MISSING_ASSERTION if the message does
 * not contain any assertion.</para></listitem>
 * </itemizedlist>
 **/
gint
lasso_login_process_response_msg(LassoLogin *login, gchar *response_msg)
{
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_process_response_msg(login, response_msg);
	}


	/* rebuild samlp:Response with response_msg */
	lasso_assign_new_gobject(profile->response, lasso_node_new_from_soap(response_msg));
	if (! LASSO_IS_SAMLP_RESPONSE(profile->response) ) {
		lasso_release_gobject(profile->response);
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	/* Validate RequestID and InResponseTo */
	if (profile->request || lasso_flag_strict_checking) {
		char *request_id = NULL;
		char *response_to = NULL;

		if (LASSO_IS_SAMLP_REQUEST(profile->request)) {
			request_id = LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->RequestID;
		}
		response_to = LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->InResponseTo;

		if ((! request_id && response_to) || /* response to an unknown request, only with
							strict checking */
		    (profile->request && ! response_to) || /* not a response to our request, because
							     no ref */
		    /* not a response to our request because of mismatch */
		    (request_id && response_to && strcmp(request_id, response_to) != 0)) {
			return critical_error(LASSO_PROFILE_ERROR_RESPONSE_DOES_NOT_MATCH_REQUEST);
		} /* else no request and no inResponseTo, IDP initiated response, ok */
	}

	/* In the artifact profile we cannot verify the signature on the message, we must wait the
	 * verification on the assertion, so for the moment the signature verification failed. */
	profile->signature_status = LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;

	xmlNode *signed_response;
	signed_response = lasso_node_get_original_xmlnode(LASSO_NODE(profile->response));
	if (signed_response && profile->remote_providerID) {
		LassoProvider *idp;

		idp = LASSO_PROVIDER(lasso_server_get_provider(profile->server,
					profile->remote_providerID));
		profile->signature_status = lasso_provider_verify_saml_signature(idp,
				signed_response, NULL);
	}

	return lasso_login_process_response_status_and_assertion(login);
}



/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AssertionArtifact", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLogin, assertionArtifact), NULL, NULL, NULL},
	{ "NameIDPolicy", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLogin, nameIDPolicy), NULL, NULL, NULL},
	{ "Assertion", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoLogin, assertion), NULL, NULL, NULL},
	{ "RequestID", SNIPPET_CONTENT | SNIPPET_PRIVATE,
		G_STRUCT_OFFSET(LassoLoginPrivate, request_id), NULL, NULL, NULL},
	{ "LoginDumpVersion", SNIPPET_ATTRIBUTE, 0, NULL, NULL, NULL},
	{ "ProtocolProfile", SNIPPET_CONTENT, 0, NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoLogin *login = LASSO_LOGIN(node);

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlSetProp(xmlnode, (xmlChar*)"LoginDumpVersion", (xmlChar*)"2");

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART)
		xmlNewTextChild(xmlnode, NULL, (xmlChar*)"ProtocolProfile", (xmlChar*)"Artifact");
	else if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST)
		xmlNewTextChild(xmlnode, NULL, (xmlChar*)"ProtocolProfile", (xmlChar*)"POST");
	else if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT)
		xmlNewTextChild(xmlnode, NULL, (xmlChar*)"ProtocolProfile", (xmlChar*)"Redirect");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLogin *login = LASSO_LOGIN(node);
	xmlNode *t;
	int rc = 0;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp((char*)t->name, "ProtocolProfile") == 0) {
			char *s;
			s = (char*)xmlNodeGetContent(t);
			if (strcmp(s, "Artifact") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
			else if (strcmp(s, "POST") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
			else if (strcmp(s, "Redirect") == 0)
				login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT;
			xmlFree(s);
		}
		t = t->next;
	}
	return 0;
}


/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoLogin *login = LASSO_LOGIN(object);

	lasso_release_string(login->private_data->soap_request_msg);
	lasso_release_gobject(login->private_data->saml2_assertion);

#ifdef LASSO_WSF_ENABLED
	lasso_release_gobject(login->private_data->resourceId);
	lasso_release_gobject(login->private_data->encryptedResourceId);
#endif
	lasso_release_string(login->private_data->request_id);
	G_OBJECT_CLASS(parent_class)->dispose(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoLogin *login)
{
	login->private_data = LASSO_LOGIN_GET_PRIVATE(login);
	login->protocolProfile = 0;
	login->assertionArtifact = NULL;
	login->nameIDPolicy = NULL;
	login->http_method = 0;
}

static void
class_init(LassoLoginClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Login");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(LassoLoginPrivate));

	G_OBJECT_CLASS(klass)->dispose = dispose;
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
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoLogin", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_login_new
 * @server: the #LassoServer
 *
 * Creates a new #LassoLogin.
 *
 * Return value: a newly created #LassoLogin object; or NULL if an error
 *     occured
 **/
LassoLogin*
lasso_login_new(LassoServer *server)
{
	LassoLogin *login = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	login = g_object_new(LASSO_TYPE_LOGIN, NULL);
	lasso_assign_gobject(LASSO_PROFILE(login)->server, server);

	return login;
}

/**
 * lasso_login_new_from_dump:
 * @server: the #LassoServer
 * @dump: XML login dump
 *
 * Restores the @dump to a new #LassoLogin.
 *
 * Return value: a newly created #LassoLogin; or NULL if an error occured.
 **/
LassoLogin*
lasso_login_new_from_dump(LassoServer *server, const gchar *dump)
{
	LassoLogin *login;

	login = (LassoLogin*)lasso_node_new_from_dump(dump);
	if (! LASSO_IS_LOGIN(login)) {
		lasso_release_gobject(login);
	} else {
		lasso_assign_gobject(login->parent.server, server);
	}
	return login;
}

/**
 * lasso_login_dump:
 * @login: a #LassoLogin
 *
 * Dumps @login content to an XML string.
 *
 * Return value:(transfer full): the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_login_dump(LassoLogin *login)
{
	return lasso_node_dump(LASSO_NODE(login));
}


/**
 * lasso_login_validate_request_msg:
 * @login: a #LassoLogin
 * @authentication_result: whether user has authenticated succesfully
 * @is_consent_obtained: whether user consent has been obtained
 *
 * Initializes a response to the authentication request received.
 *
 * Return value: 0 on success; or
 * <itemizedlist>
 * <listitem><para>#LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin object,</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_REQUEST_DENIED</para> if @authentication_result if FALSE,</listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_INVALID_SIGNATURE if signature validation of the request
 * failed,</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST if no signature was present on the
 * request,</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND if federation policy is
 * #LASSO_LIB_NAMEID_POLICY_TYPE_NONE and no federation was found in the #LassoIdentity object
 * (ID-FF 1.2 case)</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY if request policy is not one of
 * #LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED or #LASSO_LIB_NAMEID_POLICY_TYPE_ANY (ID-FF 1.2 case) or if no NameID policy was defined or the AllowCreate request flag is FALSE (SAML 2.0 case),</para></listitem>
 * <listitem><para>#LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED if @is_consent_obtained is FALSE and
 * conssent was necessary (for example if the request does not communicate that consent was already
 * obtained from the user),</para></listitem>
 * <listitem><para>#LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the requesting provider is unknown,</para></listitem>
 * </itemizedlist>
 **/
int
lasso_login_validate_request_msg(LassoLogin *login, gboolean authentication_result,
		gboolean is_consent_obtained)
{
	LassoProfile *profile;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_validate_request_msg(login,
				authentication_result, is_consent_obtained);
	}

	/* modify AuthnResponse StatusCode if user authentication is not OK */
	if (authentication_result == FALSE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
		return LASSO_LOGIN_ERROR_REQUEST_DENIED;
	}

	/* if signature is not OK => modify AuthnResponse StatusCode */
	if (profile->signature_status == LASSO_DS_ERROR_INVALID_SIGNATURE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
		return LASSO_LOGIN_ERROR_INVALID_SIGNATURE;
	}

	if (profile->signature_status == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		/* Unsigned AuthnRequest */
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST);
		return LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST;
	}

	if (profile->signature_status == 0 && authentication_result == TRUE) {
		/* process federation */
		ret = lasso_login_process_federation(login, is_consent_obtained);
		if (ret != 0)
			return ret;
	}

	lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_SUCCESS);

	return ret;
}

int
lasso_login_process_paos_response_msg(LassoLogin *login, gchar *msg)
{
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(login);

	IF_SAML2(profile) {
		return lasso_saml20_login_process_paos_response_msg(login, msg);
	}

	return 0;
}

/**
 * lasso_login_get_assertion:
 * @login: a #LassoLogin object
 *
 * Return the last build assertion.
 *
 * Return value: a #LassoNode representing the build assertion (generally a #LassoSamlAssertion when
 * using ID-FF 1.2 or a #LassoSaml2Assertion when using SAML 2.0)
 */
LassoNode*
lasso_login_get_assertion(LassoLogin *login)
{
	g_return_val_if_fail (LASSO_IS_LOGIN (login), NULL);

	if (login->private_data && login->private_data->saml2_assertion)
		return (LassoNode*)g_object_ref(login->private_data->saml2_assertion);

	return (LassoNode*)g_object_ref(login->assertion);
}
