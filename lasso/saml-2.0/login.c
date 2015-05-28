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

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "providerprivate.h"
#include "loginprivate.h"
#include "profileprivate.h"
#include "federationprivate.h"
#include "saml2_helper.h"

#include "../id-ff/providerprivate.h"
#include "../id-ff/serverprivate.h"
#include "../id-ff/login.h"
#include "../id-ff/identityprivate.h"
#include "../id-ff/sessionprivate.h"
#include "../id-ff/loginprivate.h"

#include "../xml/ecp/ecp_relaystate.h"
#include "../xml/paos_response.h"

#include "../xml/xml_enc.h"

#include "../xml/saml-2.0/samlp2_authn_request.h"
#include "../xml/saml-2.0/samlp2_response.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/saml2_audience_restriction.h"
#include "../xml/saml-2.0/saml2_authn_statement.h"
#include "../xml/saml-2.0/saml2_encrypted_element.h"
#include "../xml/saml-2.0/saml2_attribute.h"
#include "../xml/saml-2.0/saml2_attribute_statement.h"
#include "../xml/saml-2.0/saml2_attribute_value.h"
#include "../xml/saml-2.0/saml2_name_id.h"
#include "../xml/saml-2.0/saml2_xsd.h"
#include "../xml/saml-2.0/samlp2_artifact_response.h"

#include "../utils.h"

static int lasso_saml20_login_process_federation(LassoLogin *login, gboolean is_consent_obtained);
static gboolean lasso_saml20_login_must_ask_for_consent_private(LassoLogin *login);
static gint lasso_saml20_login_process_response_status_and_assertion(LassoLogin *login);
static char* lasso_saml20_login_get_assertion_consumer_service_url(LassoLogin *login,
		LassoProvider *remote_provider);
static gboolean _lasso_login_must_verify_signature(LassoProfile *profile) G_GNUC_UNUSED;
static gboolean _lasso_login_must_verify_authn_request_signature(LassoProfile *profile);

/* No need to check type of arguments, it has been done in lasso_login_* methods */

gint
lasso_saml20_login_init_authn_request(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProfile *profile = NULL;
	LassoSamlp2RequestAbstract *request = NULL;
	gchar *default_name_id_format = NULL;
	int rc = 0;

	profile = &login->parent;

	/* new */
	request = (LassoSamlp2RequestAbstract*)lasso_samlp2_authn_request_new();
	lasso_check_good_rc(lasso_saml20_profile_init_request(profile, profile->remote_providerID, FALSE,
				request, http_method, LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON));

	/* FIXME: keep old behaviour */
	login->http_method = login->parent.http_request_method;

	/* save request ID, for later check */
	lasso_assign_string(login->private_data->request_id, request->ID);
	/* set name id policy */
	lasso_assign_new_gobject(LASSO_SAMLP2_AUTHN_REQUEST(request)->NameIDPolicy,
			lasso_samlp2_name_id_policy_new());
	/* set name id policy format */
	/* no need to check server, done in init_request */
	default_name_id_format = lasso_provider_get_metadata_one_for_role(&profile->server->parent,
			LASSO_PROVIDER_ROLE_SP, "NameIDFormat");
	if (default_name_id_format) {
		/* steal the string */
		lasso_assign_new_string(LASSO_SAMLP2_AUTHN_REQUEST(request)->NameIDPolicy->Format,
				default_name_id_format);
	} else {
		lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(request)->NameIDPolicy->Format,
			LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);
	}

cleanup:
	lasso_release_gobject(request);
	return rc;
}

static gboolean want_authn_request_signed(LassoProvider *provider) {
	char *s;
	gboolean rc = FALSE;

	s = lasso_provider_get_metadata_one_for_role(provider, LASSO_PROVIDER_ROLE_IDP,
			LASSO_SAML2_METADATA_ATTRIBUTE_WANT_AUTHN_REQUEST_SIGNED);
	if (lasso_strisequal(s,"false")) {
		rc = FALSE;
	}
	lasso_release_string(s);
	return rc;
}

static gboolean authn_request_signed(LassoProvider *provider) {
	char *s;
	gboolean rc = FALSE;

	s = lasso_provider_get_metadata_one_for_role(provider, LASSO_PROVIDER_ROLE_SP,
			LASSO_SAML2_METADATA_ATTRIBUTE_AUTHN_REQUEST_SIGNED);
	if (lasso_strisequal(s,"true")) {
		rc = TRUE;
	}
	lasso_release_string(s);
	return rc;
}

static gboolean
_lasso_login_must_sign_non_authn_request(LassoLogin *profile)
{
	switch (lasso_profile_get_signature_hint(&profile->parent)) {
		case LASSO_PROFILE_SIGNATURE_HINT_MAYBE:
			return lasso_flag_add_signature;
		case LASSO_PROFILE_SIGNATURE_HINT_FORCE:
			return TRUE;
		case LASSO_PROFILE_SIGNATURE_HINT_FORBID:
			return FALSE;
		default:
			return TRUE;
	}
}

static gboolean
_lasso_login_must_sign(LassoProfile *profile)
{
	gboolean ret;
	LassoProvider *remote_provider;

	remote_provider = lasso_server_get_provider(profile->server,
			profile->remote_providerID);

	switch (lasso_profile_get_signature_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_HINT_MAYBE:
			/* If our metadatas say that we sign, then we sign,
			 * If the IdP says that he wants our signature, then we sign
			 * Otherwise we do not.
			 */
			ret = authn_request_signed(&profile->server->parent)
				|| want_authn_request_signed(remote_provider);
			return ret;
		case LASSO_PROFILE_SIGNATURE_HINT_FORCE:
			return TRUE;
		case LASSO_PROFILE_SIGNATURE_HINT_FORBID:
			return FALSE;
	}
	g_assert(0);
	return TRUE;
}

static gboolean
_lasso_login_must_verify_authn_request_signature(LassoProfile *profile) {
	LassoProvider *remote_provider;

	remote_provider = lasso_server_get_provider(profile->server,
			profile->remote_providerID);

	switch (lasso_profile_get_signature_verify_hint(profile)) {
			/* If our metadatas say that we want signature, then we verify,
			 * If the SP says that he signs, then we verify
			 * Otherwise we do not.
			 */
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			return want_authn_request_signed(&profile->server->parent) ||
				authn_request_signed(remote_provider);
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			return FALSE;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
			return TRUE;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST:
			break;
	}
	g_assert(0);
	return TRUE;
}

static gboolean
_lasso_login_must_verify_signature(LassoProfile *profile) {
	switch (lasso_profile_get_signature_verify_hint(profile)) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			return lasso_flag_verify_signature;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			return FALSE;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
			return TRUE;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST:
			break;
	}
	g_assert(0);
	return TRUE;
}

gint
lasso_saml20_login_build_authn_request_msg(LassoLogin *login)
{
	char *url = NULL;
	gboolean must_sign = TRUE;
	LassoProfile *profile;
	LassoSamlp2AuthnRequest *authn_request;
	int rc = 0;

	profile = &login->parent;

	lasso_extract_node_or_fail(authn_request, profile->request, SAMLP2_AUTHN_REQUEST,
			LASSO_PROFILE_ERROR_INVALID_REQUEST);

	/* default is to sign ! */
	must_sign = _lasso_login_must_sign(profile);

	if (! must_sign) {
		lasso_node_remove_signature(profile->request);
	}

	/* support old way of doing PAOS */
	if (login->http_method == LASSO_HTTP_METHOD_SOAP
			&& lasso_strisequal(authn_request->ProtocolBinding,LASSO_SAML2_METADATA_BINDING_PAOS)) {
		login->http_method = LASSO_HTTP_METHOD_PAOS;
	}

	if (login->http_method == LASSO_HTTP_METHOD_PAOS) {

		/*
		 * PAOS is special, the url passed to build_request is the
		 * AssertionConsumerServiceURL of this SP, not the
		 * destination.
		 */
		if (authn_request->AssertionConsumerServiceURL) {
			url = authn_request->AssertionConsumerServiceURL;
			if (!lasso_saml20_provider_check_assertion_consumer_service_url(
					LASSO_PROVIDER(profile->server), url, LASSO_SAML2_METADATA_BINDING_PAOS)) {
				rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
				goto cleanup;
			}
		} else {
			url = lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(
					LASSO_PROVIDER(profile->server), LASSO_SAML2_METADATA_BINDING_PAOS);
			lasso_assign_string(authn_request->AssertionConsumerServiceURL, url);
		}
	}


	lasso_check_good_rc(lasso_saml20_profile_build_request_msg(profile, "SingleSignOnService",
				login->http_method, url));

cleanup:
	return rc;
}

int
lasso_saml20_login_process_authn_request_msg(LassoLogin *login, const char *authn_request_msg)
{
	LassoNode *request = NULL;
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2StatusResponse *response = NULL;
	LassoSamlp2AuthnRequest *authn_request = NULL;
	LassoProvider *remote_provider = NULL;
	LassoServer *server = NULL;
	const gchar *protocol_binding = NULL;
	const char *status1 = LASSO_SAML2_STATUS_CODE_RESPONDER;
	const char *status2 = NULL;
	int rc = 0;

	if (authn_request_msg == NULL) {
		if (profile->request == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
		}

		/* AuthnRequest already set by .._init_idp_initiated_authn_request, or from a
		 * previously failed call to process_authn_request that we retry. */
		request = lasso_ref(profile->request);
	} else {
		request = lasso_samlp2_authn_request_new();
		lasso_check_good_rc(lasso_saml20_profile_process_any_request(profile, request, authn_request_msg));
	}
	if (! LASSO_IS_SAMLP2_AUTHN_REQUEST(request)) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	authn_request = LASSO_SAMLP2_AUTHN_REQUEST(request);
	/* intialize the response */
	response = (LassoSamlp2StatusResponse*) lasso_samlp2_response_new();
	lasso_assign_string(response->InResponseTo,
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	/* reset response binding */
	login->protocolProfile = 0;

	/* find the remote provider */
	if (! authn_request->parent.Issuer || ! authn_request->parent.Issuer->content) {
		rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
		goto cleanup;
	}
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (remote_provider == NULL) {
		rc = LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER;
		goto cleanup;
	}
	lasso_extract_node_or_fail(server, lasso_profile_get_server(&login->parent), SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	remote_provider->role = LASSO_PROVIDER_ROLE_SP;
	server->parent.role = LASSO_PROVIDER_ROLE_IDP;

	if (((authn_request->ProtocolBinding != NULL) ||
			(authn_request->AssertionConsumerServiceURL != NULL)) &&
			(authn_request->AssertionConsumerServiceIndex != -1))
	{
		rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
		goto cleanup;
	}

	/* try to find a protocol profile for sending the response */
	protocol_binding = authn_request->ProtocolBinding;
	if (protocol_binding || authn_request->AssertionConsumerServiceURL)
	{
		if (authn_request->AssertionConsumerServiceURL) {
			if (protocol_binding) {
				if (! lasso_saml20_provider_check_assertion_consumer_service_url(
							remote_provider, 
							authn_request->AssertionConsumerServiceURL,
							authn_request->ProtocolBinding)) {
					// Sent ACS URL is unknown
					rc = LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
					goto cleanup;
				}
			} else {
				// Only ACS URL sent, choose the first associated binding
				protocol_binding = lasso_saml20_provider_get_assertion_consumer_service_binding_by_url(
						remote_provider, authn_request->AssertionConsumerServiceURL);
				if (! protocol_binding) {
					rc = LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
					goto cleanup;
				}
				lasso_assign_string(authn_request->ProtocolBinding,
						protocol_binding);
			}
		}

		if (lasso_strisequal(protocol_binding,LASSO_SAML2_METADATA_BINDING_ARTIFACT)) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
		} else if (lasso_strisequal(protocol_binding,LASSO_SAML2_METADATA_BINDING_POST)) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
		} else if (lasso_strisequal(protocol_binding,LASSO_SAML2_METADATA_BINDING_SOAP)) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
		} else if (lasso_strisequal(protocol_binding,LASSO_SAML2_METADATA_BINDING_REDIRECT)) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT;
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
		} else if (lasso_strisequal(protocol_binding,LASSO_SAML2_METADATA_BINDING_PAOS)) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
		} else {
			rc = LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
			goto cleanup;
		}
	} else {
		/* protocol binding not set; so it will look into
		 * AssertionConsumerServiceIndex
		 * Also, if AssertionConsumerServiceIndex is not set in request,
		 * its value will be -1, which is just the right value to get
		 * default assertion consumer...  (convenient)
		 */
		gchar *binding;
		int service_index = authn_request->AssertionConsumerServiceIndex;

		binding = lasso_saml20_provider_get_assertion_consumer_service_binding(
				remote_provider, service_index);
		if (binding == NULL) {
			if (service_index == -1) {
				goto_cleanup_with_rc(LASSO_LOGIN_ERROR_NO_DEFAULT_ENDPOINT);
			} else {
				goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
			}
		} else if (lasso_strisequal(binding,"HTTP-Artifact")) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
		} else if (lasso_strisequal(binding,"HTTP-POST")) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
		} else if (lasso_strisequal(binding,"HTTP-Redirect")) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT;
		} else if (lasso_strisequal(binding,"SOAP")) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
		} else if (lasso_strisequal(binding,"PAOS")) {
			login->protocolProfile = LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP;
		}
		lasso_release_string(binding);
	}


	if (_lasso_login_must_verify_authn_request_signature(profile) && profile->signature_status)
	{
		status1 = LASSO_SAML2_STATUS_CODE_REQUESTER;
		status2 = LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE;
		rc = profile->signature_status;
	} else {
		status1 = LASSO_SAML2_STATUS_CODE_SUCCESS;
		status2 = NULL;
	}
	lasso_saml20_profile_init_response(profile, response,
				status1, status2);
cleanup:
	lasso_release_gobject(request);
	lasso_release_gobject(response);
	return rc;
}


gboolean
lasso_saml20_login_must_authenticate(LassoLogin *login)
{
	LassoSamlp2AuthnRequest *request;
	gboolean matched = TRUE;
	GList *assertions = NULL;
	LassoProfile *profile = &login->parent;

	if (! LASSO_IS_SAMLP2_AUTHN_REQUEST(profile->request))
		return FALSE;

	request = LASSO_SAMLP2_AUTHN_REQUEST(profile->request);
	if (request->ForceAuthn == TRUE && request->IsPassive == FALSE)
		return TRUE;

	if (request->RequestedAuthnContext) {
		char *comparison = request->RequestedAuthnContext->Comparison;
		GList *class_refs = request->RequestedAuthnContext->AuthnContextClassRef;
		char *class_ref;
		GList *t1, *t2;
		int compa = -1;

		if (comparison == NULL || lasso_strisequal(comparison,"exact")) {
			compa = 0;
		} else if (lasso_strisequal(comparison,"minimum")) {
			message(G_LOG_LEVEL_CRITICAL, "'minimum' comparison is not implemented");
			compa = 1;
		} else if (lasso_strisequal(comparison,"better")) {
			message(G_LOG_LEVEL_CRITICAL, "'better' comparison is not implemented");
			compa = 2;
		} else if (lasso_strisequal(comparison,"maximum")) {
			message(G_LOG_LEVEL_CRITICAL, "'maximum' comparison is not implemented");
			compa = 3;
		}

		if (class_refs) {
			matched = FALSE;
		}

		assertions = lasso_session_get_assertions(profile->session, NULL);
		for (t1 = class_refs; t1 && !matched; t1 = g_list_next(t1)) {
			class_ref = t1->data;
			for (t2 = assertions; t2 && !matched; t2 = g_list_next(t2)) {
				LassoSaml2Assertion *assertion;
				LassoSaml2AuthnStatement *as = NULL;
				char *method;
				GList *t3;

				if (LASSO_IS_SAML2_ASSERTION(t2->data) == FALSE) {
					continue;
				}

				assertion = t2->data;

				for (t3 = assertion->AuthnStatement; t3; t3 = g_list_next(t3)) {
					if (LASSO_IS_SAML2_AUTHN_STATEMENT(t3->data)) {
						as = t3->data;
						break;
					}
				}

				if (as == NULL)
					continue;

				if (as->AuthnContext == NULL)
					continue;

				method = as->AuthnContext->AuthnContextClassRef;

				switch (compa) {
				case 1: /* minimum */
					/* XXX: implement 'minimum' comparison */
				case 2: /* better */
					/* XXX: implement 'better' comparison */
				case 3: /* maximum */
					/* XXX: implement 'maximum' comparison */
				case 0: /* exact */
					if (lasso_strisequal(method,class_ref)) {
						matched = TRUE;
					}
					break;
				default: /* never reached */
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
	if (assertions) {
		lasso_release_list(assertions);
	}
	if (matched == FALSE && request->IsPassive == FALSE)
		return TRUE;
	if (profile->identity == NULL && request->IsPassive) {
		lasso_saml20_profile_set_response_status_responder(LASSO_PROFILE(login),
				LASSO_SAML2_STATUS_CODE_NO_PASSIVE);
		return FALSE;
	}
	return FALSE;
}

static gboolean
lasso_saml20_login_must_ask_for_consent_private(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2NameIDPolicy *name_id_policy;
	char *consent;
	LassoFederation *federation;
	const char *name_id_sp_name_qualifier = NULL;
	LassoProvider *remote_provider;
	gboolean rc = TRUE;

	name_id_policy = LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy;

	if (name_id_policy) {
		char *format = name_id_policy->Format;
		if (lasso_strisequal(format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT)) {
			goto_cleanup_with_rc (FALSE)
		}
		if (name_id_policy->AllowCreate == FALSE) {
			goto_cleanup_with_rc (FALSE)
		}
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	name_id_sp_name_qualifier = lasso_provider_get_sp_name_qualifier(remote_provider);

	/* if something goes wrong better to ask thant to let go */
	if (name_id_sp_name_qualifier == NULL)
		goto_cleanup_with_rc (TRUE)

	if (profile->identity && profile->identity->federations) {
		federation = g_hash_table_lookup(profile->identity->federations,
				name_id_sp_name_qualifier);
		if (federation) {
			goto_cleanup_with_rc (FALSE)
		}
	}

	consent = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Consent;
	if (consent == NULL)
		goto_cleanup_with_rc (FALSE)

	if (lasso_strisequal(consent,LASSO_SAML2_CONSENT_OBTAINED))
		goto_cleanup_with_rc (FALSE)

	if (lasso_strisequal(consent,LASSO_SAML2_CONSENT_PRIOR))
		goto_cleanup_with_rc (FALSE)

	if (lasso_strisequal(consent,LASSO_SAML2_CONSENT_IMPLICIT))
		goto_cleanup_with_rc (FALSE)

	if (lasso_strisequal(consent,LASSO_SAML2_CONSENT_EXPLICIT))
		goto_cleanup_with_rc (FALSE)

	if (lasso_strisequal(consent,LASSO_SAML2_CONSENT_UNAVAILABLE))
		goto_cleanup_with_rc (TRUE)

	if (lasso_strisequal(consent,LASSO_SAML2_CONSENT_INAPPLICABLE))
		goto_cleanup_with_rc (TRUE)

cleanup:
	return rc;
}

gboolean
lasso_saml20_login_must_ask_for_consent(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);

	if (LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->IsPassive)
		return FALSE;

	return lasso_saml20_login_must_ask_for_consent_private(login);
}

int
lasso_saml20_login_validate_request_msg(LassoLogin *login, gboolean authentication_result,
		gboolean is_consent_obtained)
{
	LassoProfile *profile;
	int rc = 0;

	profile = LASSO_PROFILE(login);

	if (authentication_result == FALSE) {
		lasso_saml20_profile_set_response_status_responder(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		goto_cleanup_with_rc(LASSO_LOGIN_ERROR_REQUEST_DENIED);
	}

	if (_lasso_login_must_verify_authn_request_signature(profile) && profile->signature_status)
	{
		lasso_saml20_profile_set_response_status_requester(profile,
					LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);

		if (profile->signature_status == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
			goto_cleanup_with_rc(LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST);
		}
		goto_cleanup_with_rc(LASSO_LOGIN_ERROR_INVALID_SIGNATURE);
	}

	rc = lasso_saml20_login_process_federation(login, is_consent_obtained);
	if (rc == LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND) {
		lasso_saml20_profile_set_response_status_requester(profile,
			LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		goto cleanup;
	}
	/* UNKNOWN_PROVIDER, CONSENT_NOT_OBTAINED */
	if (rc) {
		lasso_saml20_profile_set_response_status_responder(profile,
			LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		goto cleanup;
	}

	lasso_saml20_profile_set_response_status_success(profile, NULL);
cleanup:

	return rc;
}

static int
lasso_saml20_login_process_federation(LassoLogin *login, gboolean is_consent_obtained)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSamlp2NameIDPolicy *name_id_policy;
	char *name_id_policy_format = NULL;
	LassoFederation *federation;
	const char *name_id_sp_name_qualifier = NULL;
	LassoProvider *remote_provider;
	int rc = 0;

	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (! LASSO_IS_PROVIDER(remote_provider)) {
		goto_cleanup_with_rc (LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER);
	}

	if (! LASSO_IS_SAMLP2_AUTHN_REQUEST(profile->request)) {
		goto_cleanup_with_rc(critical_error(LASSO_PROFILE_ERROR_INVALID_REQUEST));
	}

	name_id_policy = ((LassoSamlp2AuthnRequest*)profile->request)->NameIDPolicy;

	if (name_id_policy) {
		name_id_policy_format = name_id_policy->Format;
	}

	if (! name_id_policy_format) {
		name_id_policy_format = lasso_provider_get_default_name_id_format(remote_provider);
	}

	lasso_assign_string(login->nameIDPolicy, name_id_policy_format);

	if (lasso_saml20_login_must_ask_for_consent_private(login) && !is_consent_obtained) {
		goto_cleanup_with_rc (LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED)
	}
	if (lasso_strisnotequal(name_id_policy_format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT)) {
		/* non persistent case, TRANSIENT is handled by lasso_login_build_assertion() and
		 * other format are the sole responsibility of the caller */
		goto_cleanup_with_rc (0)
	}

	/* PERSISTENT case, try to federation or find an existing federation */
	name_id_sp_name_qualifier = lasso_provider_get_sp_name_qualifier(remote_provider);
	if (name_id_sp_name_qualifier == NULL) {
		goto_cleanup_with_rc (LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER);
	}

	/* search a federation in the identity */
	federation = lasso_identity_get_federation(profile->identity, name_id_sp_name_qualifier);
	if (! federation && ( ! name_id_policy || name_id_policy->AllowCreate == FALSE)) {
		goto_cleanup_with_rc (LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND)
	}
	if (! federation && name_id_policy && name_id_policy->AllowCreate) {
		federation = lasso_federation_new(name_id_sp_name_qualifier);
		lasso_saml20_federation_build_local_name_identifier(federation,
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT,
				NULL);
		lasso_assign_string(LASSO_SAML2_NAME_ID(federation->local_nameIdentifier)->SPNameQualifier,
				name_id_sp_name_qualifier);
		lasso_identity_add_federation(profile->identity, federation);
	}

	lasso_assign_gobject(profile->nameIdentifier, federation->local_nameIdentifier);

cleanup:
	return rc;
}

static LassoFederation*
_lasso_login_saml20_get_federation(LassoLogin *login) {
	LassoFederation *federation = NULL;
	const char *name_id_sp_name_qualifier = NULL;


	name_id_sp_name_qualifier = lasso_provider_get_sp_name_qualifier(
			lasso_server_get_provider(login->parent.server, login->parent.remote_providerID));
	federation = lasso_identity_get_federation(login->parent.identity, name_id_sp_name_qualifier);
	return federation;
}

int
lasso_saml20_login_build_assertion(LassoLogin *login,
		const char *authenticationMethod,
		const char *authenticationInstant,
		G_GNUC_UNUSED const char *notBefore,
		const char *notOnOrAfter)
{
	LassoProfile *profile = &login->parent;
	LassoSaml2Assertion *assertion = NULL;
	LassoSaml2AudienceRestriction *audience_restriction = NULL;
	LassoSamlp2NameIDPolicy *name_id_policy = NULL;
	LassoSaml2NameID *name_id = NULL;
	LassoSaml2AuthnStatement *authentication_statement;
	LassoProvider *provider = NULL;
	LassoSamlp2Response *response = NULL;
	LassoSamlp2RequestAbstract *request_abstract = NULL;
	LassoSamlp2AuthnRequest *authn_request = NULL;
	gboolean do_encrypt_nameid = FALSE;
	gboolean do_encrypt_assertion = FALSE;
	int rc = 0;

	provider = lasso_server_get_provider(profile->server, profile->remote_providerID);

	if (provider) {
		do_encrypt_nameid = lasso_provider_get_encryption_mode(provider) &
			LASSO_ENCRYPTION_MODE_NAMEID;
		do_encrypt_assertion = lasso_provider_get_encryption_mode(provider) &
			LASSO_ENCRYPTION_MODE_ASSERTION;
	}

	if (LASSO_IS_SAMLP2_AUTHN_REQUEST(profile->request)) {
		authn_request = (LassoSamlp2AuthnRequest*)profile->request;
		request_abstract = &authn_request->parent;
	}
	goto_cleanup_if_fail_with_rc(LASSO_IS_SAMLP2_RESPONSE(profile->response),
			LASSO_PROFILE_ERROR_MISSING_RESPONSE);

	assertion = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());
	assertion->ID = lasso_build_unique_id(32);
	lasso_assign_string(assertion->Version, "2.0");
	assertion->IssueInstant = lasso_get_current_time();
	assertion->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	assertion->Conditions = LASSO_SAML2_CONDITIONS(lasso_saml2_conditions_new());
	lasso_assign_string(assertion->Conditions->NotOnOrAfter, notOnOrAfter);

	audience_restriction = LASSO_SAML2_AUDIENCE_RESTRICTION(
			lasso_saml2_audience_restriction_new());
	lasso_assign_string(audience_restriction->Audience, profile->remote_providerID);
	lasso_list_add_new_gobject(assertion->Conditions->AudienceRestriction, audience_restriction);

	assertion->Subject = LASSO_SAML2_SUBJECT(lasso_saml2_subject_new());
	assertion->Subject->SubjectConfirmation = LASSO_SAML2_SUBJECT_CONFIRMATION(
			lasso_saml2_subject_confirmation_new());
	assertion->Subject->SubjectConfirmation->Method = g_strdup(
			LASSO_SAML2_CONFIRMATION_METHOD_BEARER);
	assertion->Subject->SubjectConfirmation->SubjectConfirmationData =
		LASSO_SAML2_SUBJECT_CONFIRMATION_DATA(
			lasso_saml2_subject_confirmation_data_new());
	lasso_assign_string(
		assertion->Subject->SubjectConfirmation->SubjectConfirmationData->NotOnOrAfter,
		notOnOrAfter);

	/* If request is present, refer to it in the response */
	if (authn_request) {
		if (request_abstract->ID) {
			lasso_assign_string(assertion->Subject->SubjectConfirmation->SubjectConfirmationData->InResponseTo,
					request_abstract->ID);
			/*
			 * It MUST NOT contain a NotBefore attribute. If
			 * the containing message is in response to an <AuthnRequest>,
			 * then the InResponseTo attribute MUST match the request's ID.
			 */
			lasso_release_string(assertion->Subject->SubjectConfirmation->SubjectConfirmationData->NotBefore);
		}
		name_id_policy = authn_request->NameIDPolicy;
	}
	/* TRANSIENT */
	if (!name_id_policy || name_id_policy->Format == NULL ||
			lasso_strisequal(name_id_policy->Format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED) ||
			lasso_strisequal(name_id_policy->Format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT)) {
		char *id = lasso_build_unique_id(32);

		name_id = (LassoSaml2NameID*)lasso_saml2_name_id_new_with_string(id);
		lasso_release_string(id);
		lasso_assign_string(name_id->NameQualifier,
				lasso_provider_get_sp_name_qualifier(&profile->server->parent));
		lasso_assign_string(name_id->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);
		assertion->Subject->NameID = name_id;
	/* FEDERATED */
	} else if (lasso_strisequal(name_id_policy->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT) ||
			lasso_strisequal(name_id_policy->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED))
		{
		LassoFederation *federation;

		federation = _lasso_login_saml20_get_federation(login);
		goto_cleanup_if_fail_with_rc(federation != NULL,
				LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);

		if (lasso_strisequal(name_id_policy->Format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED)) {
			do_encrypt_nameid = TRUE;
		}
		lasso_assign_gobject(assertion->Subject->NameID,
				federation->local_nameIdentifier);
	/* ALL OTHER KIND OF NAME ID FORMATS */
	} else {
		/* caller must set the name identifier content afterwards */
		name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
		lasso_assign_string(name_id->NameQualifier,
				LASSO_PROVIDER(profile->server)->ProviderID);
		lasso_assign_string(name_id->Format, name_id_policy->Format);
		assertion->Subject->NameID = name_id;
		if (do_encrypt_nameid) {
			message(G_LOG_LEVEL_WARNING, "NameID encryption is currently not "
					"supported with non transient or persisent NameID format");
			do_encrypt_nameid = FALSE;
		}
	}

	authentication_statement = LASSO_SAML2_AUTHN_STATEMENT(lasso_saml2_authn_statement_new());
	authentication_statement->AuthnInstant = g_strdup(authenticationInstant);
	authentication_statement->AuthnContext = LASSO_SAML2_AUTHN_CONTEXT(
			lasso_saml2_authn_context_new());
	authentication_statement->AuthnContext->AuthnContextClassRef = g_strdup(
			authenticationMethod);

	/* if remote provider supports logout profile, add a session index == ID of the assertion */
	if (lasso_provider_get_first_http_method(&login->parent.server->parent,
				provider, LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT) != LASSO_HTTP_METHOD_NONE) {
		lasso_assign_string(authentication_statement->SessionIndex, assertion->ID);
	}
	lasso_list_add_new_gobject(assertion->AuthnStatement, authentication_statement);

	/* Save signing material in assertion private datas to be able to sign later */
	lasso_check_good_rc(lasso_server_saml2_assertion_setup_signature(profile->server,
				assertion));

	/* Encrypt NameID */
	if (do_encrypt_nameid) {
		/* store assertion in session object */
		if (profile->session == NULL) {
			profile->session = lasso_session_new();
		}

		lasso_session_add_assertion(profile->session, profile->remote_providerID,
				LASSO_NODE(assertion));

		/* FIXME: as with assertions, it should be possible to setup encryption of NameID for later */
		goto_cleanup_if_fail_with_rc(provider != NULL, LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

		assertion->Subject->EncryptedID = (LassoSaml2EncryptedElement*)lasso_node_encrypt(
			(LassoNode*)assertion->Subject->NameID,
			lasso_provider_get_encryption_public_key(provider),
			lasso_provider_get_encryption_sym_key_type(provider),
			provider->ProviderID);
		goto_cleanup_if_fail_with_rc(assertion->Subject->EncryptedID != NULL,
				LASSO_DS_ERROR_ENCRYPTION_FAILED);
		lasso_release_gobject(assertion->Subject->NameID);
	}

	/* Save encryption material in assertion private datas to be able to encrypt later */
	if (do_encrypt_assertion) {
		lasso_node_set_encryption((LassoNode*)assertion,
				lasso_provider_get_encryption_public_key(provider),
				lasso_provider_get_encryption_sym_key_type(provider));
	}

	response = LASSO_SAMLP2_RESPONSE(profile->response);
	lasso_list_add_gobject(response->Assertion, assertion);
	lasso_assign_gobject(login->private_data->saml2_assertion, assertion);
cleanup:
	lasso_release_gobject(assertion);
	return rc;
}

gint
lasso_saml20_login_build_artifact_msg(LassoLogin *login, LassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *url;
	LassoSaml2Assertion *assertion;
	LassoSamlp2StatusResponse *response;
	int rc = 0;

	profile = &login->parent;

	if (profile->remote_providerID == NULL)
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);

	if (http_method != LASSO_HTTP_METHOD_ARTIFACT_GET && http_method != LASSO_HTTP_METHOD_ARTIFACT_POST) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	if (! LASSO_IS_SAMLP2_RESPONSE(profile->response)) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_RESPONSE);
	}
	response = (LassoSamlp2StatusResponse*)profile->response;
	/* XXX: why checking now ? */
	if (response->Status == NULL || response->Status->StatusCode == NULL
			|| response->Status->StatusCode->Value == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	url = lasso_saml20_login_get_assertion_consumer_service_url(login, remote_provider);
	assertion = login->private_data->saml2_assertion;
	if (LASSO_IS_SAML2_ASSERTION(assertion) && url) {
		LassoSaml2SubjectConfirmationData *subject_confirmation_data;

		subject_confirmation_data =
			lasso_saml2_assertion_get_subject_confirmation_data(assertion, TRUE);
		lasso_assign_string(subject_confirmation_data->Recipient, url);
	}

	/* If there is a non-encrypted NameID, fix the assertion in the session */
	if (assertion && assertion->Subject && assertion->Subject->NameID) {
		/* store assertion in session object */
		if (profile->session == NULL) {
			profile->session = lasso_session_new();
		}
		lasso_session_add_assertion(profile->session, profile->remote_providerID,
				LASSO_NODE(assertion));
	}


	lasso_check_good_rc(lasso_saml20_profile_build_response_msg(profile, NULL, http_method,
				url));

cleanup:
	lasso_release_string(url);
	return rc;
}


gint
lasso_saml20_login_init_request(LassoLogin *login, gchar *response_msg,
		LassoHttpMethod response_http_method)
{
	return lasso_saml20_profile_init_artifact_resolve(LASSO_PROFILE(login),
			LASSO_PROVIDER_ROLE_IDP, response_msg, response_http_method);
}


gint
lasso_saml20_login_build_request_msg(LassoLogin *login)
{
	LassoProfile *profile;
	lasso_error_t rc = 0;

	profile = &login->parent;
	if (_lasso_login_must_sign_non_authn_request(login)) {
		rc = lasso_profile_saml20_setup_message_signature(profile, profile->request);
		if (rc != 0) {
			return rc;
		}
	} else {
		lasso_node_remove_signature(profile->request);
	}
	return lasso_saml20_profile_build_request_msg(profile, "ArtifactResolutionService",
			LASSO_HTTP_METHOD_SOAP, profile->msg_url);
}

gint
lasso_saml20_login_process_request_msg(LassoLogin *login, gchar *request_msg)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	int rc = 0;

	rc = lasso_saml20_profile_process_artifact_resolve(profile, request_msg);
	if (rc != 0) {
		return rc;
	}
	/* compat with liberty id-ff code */
	lasso_assign_new_string(login->assertionArtifact, lasso_profile_get_artifact(profile));
	return 0;
}

gint
lasso_saml20_login_build_response_msg(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoProvider *remote_provider;
	LassoSaml2Assertion *assertion;
	int rc = 0;

	if (login->protocolProfile == LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_LECP) {
		const char *assertionConsumerURL;

		lasso_check_good_rc(lasso_profile_saml20_setup_message_signature(profile,
					profile->response));
		remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
			return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

		assertionConsumerURL = lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(
                         remote_provider, LASSO_SAML2_METADATA_BINDING_PAOS);

		assertion = login->private_data->saml2_assertion;
		if (LASSO_IS_SAML2_ASSERTION(assertion) == TRUE) {
			assertion->Subject->SubjectConfirmation->SubjectConfirmationData->Recipient
						= g_strdup(assertionConsumerURL);
		}

		/* If response is signed it MUST have Destination attribute, optional otherwise */
		lasso_assign_string(((LassoSamlp2StatusResponse*)profile->response)->Destination,
					assertionConsumerURL);

		/* build an ECP SOAP Response */
		lasso_assign_new_string(profile->msg_body, lasso_node_export_to_ecp_soap_response(
					LASSO_NODE(profile->response), assertionConsumerURL));
		return rc;
	}

	return lasso_saml20_profile_build_artifact_response(LASSO_PROFILE(login));

cleanup:
	return rc;
}

/**
 * lasso_saml20_login_process_paos_response_msg:
 * @login: a #LassoLogin profile object
 * @msg: ECP to SP PAOS message
 *
 * Process an ECP to SP PAOS response message.
 *
 * SAML2 Profile for ECP (Section 4.2) defines these steps for an ECP
 * transaction
 *
 * 1. ECP issues HTTP Request to SP
 * 2. SP issues <AuthnRequest> to ECP using PAOS
 * 3. ECP determines IdP
 * 4. ECP conveys <AuthnRequest> to IdP using SOAP
 * 5. IdP identifies principal
 * 6. IdP issues <Response> to ECP, targeted at SP using SOAP
 * 7. ECP conveys <Response> to SP using PAOS
 * 8. SP grants or denies access to principal
 *
 * This function is used in the implemention of Step 8 in an SP. The
 * ECP response from Step 7 has been received from the ECP client, the
 * SP must now parse the response and act upon the result of the Authn
 * request the SP issued in Step 2. If the SOAP body contains a
 * samlp:Response with a saml:Assertion the assertion is processed in
 * the context of the @login parameter.
 *
 * The response may contain in the SOAP header a paos:Response or
 * ecp:RelayState elment, both are optional. If the ecp:RelayState is
 * present it is assigned to the #LassoProfile.msg_relayState
 * field. If the paos:Response is present it's refToMessageID
 * attribute is assigned to the #LassoProfile.msg_messageID field.
 */
gint
lasso_saml20_login_process_paos_response_msg(LassoLogin *login, gchar *msg)
{
	LassoSoapHeader *header = NULL;
	LassoProfile *profile;
	int rc1, rc2;

	lasso_null_param(msg);

	profile = LASSO_PROFILE(login);

	rc1 = lasso_saml20_profile_process_soap_response_with_headers(profile, msg, &header);

	/*
	 * If the SOAP message contained a header check for the optional
     * paos:Response and ecp:RelayState elements, if they exist extract their
     * values into the profile.
	 */
	if (header) {
		GList *i = NULL;
		LassoEcpRelayState *ecp_relaystate = NULL;
		LassoPaosResponse *paos_response = NULL;

		lasso_foreach(i, header->Other) {
			if (!ecp_relaystate && LASSO_IS_ECP_RELAYSTATE(i->data)) {
				ecp_relaystate = (LassoEcpRelayState *)i->data;
			} else if (!paos_response && LASSO_IS_PAOS_RESPONSE(i->data)) {
				paos_response = (LassoPaosResponse *)i->data;
			}
			if (ecp_relaystate && paos_response) break;
		}
		if (ecp_relaystate) {
			lasso_assign_string(profile->msg_relayState, ecp_relaystate->RelayState);
		}
		if (paos_response) {
			lasso_profile_set_message_id(profile, paos_response->refToMessageID);
		}
	}

	rc2 = lasso_saml20_login_process_response_status_and_assertion(login);
	if (rc1) {
		return rc1;
	}
	return rc2;

}

/**
 * lasso_saml20_login_process_authn_response_msg:
 * @login: a #LassoLogin profile object
 * @authn_response_msg: a string containg a response msg to an #LassoSaml2AuthnRequest
 *
 * Parse a response made using binding HTTP-Redirect, HTTP-Post or HTTP-SOAP. Any signature
 * validation error is reported.
 *
 * Return value: 0 if succesfull, an error code otherwise.
 */
gint
lasso_saml20_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg)
{
	LassoProfile *profile = NULL;
	LassoSamlp2Response *samlp2_response = NULL;
	LassoHttpMethod response_method = LASSO_HTTP_METHOD_NONE;
	int rc = 0;

	lasso_null_param(authn_response_msg);

	/* parse the message */
	profile = LASSO_PROFILE(login);
	samlp2_response = (LassoSamlp2Response*)lasso_samlp2_response_new();
	rc = lasso_saml20_profile_process_any_response(profile,
		(LassoSamlp2StatusResponse*)samlp2_response, &response_method,
		authn_response_msg);

	if (response_method != LASSO_HTTP_METHOD_POST) {
		/* Only HTTP-Post binding is possible through this method */
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
	}

	/* Skip signature errors, let lasso_saml20_login_process_response_status_and_assertion
	 * handle them */
	goto_cleanup_if_fail (rc == 0 || rc == LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS || rc ==
			LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE);

	rc = lasso_saml20_login_process_response_status_and_assertion(login);
cleanup:
	lasso_release_gobject(samlp2_response);
	return rc;
}

gint
lasso_saml20_login_process_response_msg(LassoLogin *login, gchar *response_msg)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	int rc = 0;

	rc = lasso_saml20_profile_process_artifact_response(profile, response_msg);
	if (rc) {
		return rc;
	}
	if (LASSO_IS_SAMLP2_ARTIFACT_RESPONSE(login->parent.response)) {
		return lasso_saml20_login_process_authn_request_msg(login, NULL);
	} else {
		return lasso_saml20_login_process_response_status_and_assertion(login);
	}
}

static gint
lasso_saml20_login_check_assertion_signature(LassoLogin *login,
		LassoSaml2Assertion *assertion)
{
	xmlNode *original_node = NULL;
	LassoSaml2NameID *Issuer = NULL;
	LassoServer *server = NULL;
	LassoProfile *profile = NULL;
	char *remote_provider_id = NULL;
	LassoProvider *remote_provider;
	int rc = 0;

	lasso_bad_param(SAML2_ASSERTION, assertion);

	profile = (LassoProfile*)login;
	lasso_extract_node_or_fail(server, lasso_profile_get_server(profile),
			SERVER, LASSO_PROFILE_ERROR_MISSING_SERVER);

	/* Get an issuer */
	Issuer = assertion->Issuer;
	if (! Issuer || /* No issuer */
			! Issuer->content || /* No issuer content */
			(Issuer->Format &&
			 lasso_strisnotequal(Issuer->Format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY)))
		/* Issuer format is not entity */
	{
		rc = LASSO_PROFILE_ERROR_MISSING_ISSUER;
		goto cleanup;
	} else {
		remote_provider_id = Issuer->content;
	}
	remote_provider = lasso_server_get_provider(server, remote_provider_id);
	goto_cleanup_if_fail_with_rc(remote_provider, LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	/* Get the original node */
	original_node = lasso_node_get_original_xmlnode(LASSO_NODE(assertion));
	goto_cleanup_if_fail_with_rc(original_node, LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE);

	rc = profile->signature_status = lasso_provider_verify_saml_signature(remote_provider, original_node, NULL);

#define log_verify_assertion_signature_error(msg) \
			message(G_LOG_LEVEL_WARNING, "Could not verify signature of assertion" \
					"ID:%s, " msg ".", assertion->ID);
cleanup:
	switch (rc) {
		case LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND:
			log_verify_assertion_signature_error("Issuer is unknown");
			break;
		case LASSO_PROFILE_ERROR_MISSING_ISSUER:
			log_verify_assertion_signature_error(
				"no Issuer found or Issuer has bad format");
			break;
		case LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE:
			log_verify_assertion_signature_error(
				" the original xmlNode is certainly not accessible anymore");

		default:
			break;
	}
#undef log_verify_assertion_signature_error
	return rc;
}

static gboolean
_lasso_check_assertion_issuer(LassoSaml2Assertion *assertion, const gchar *provider_id)
{
	if (! LASSO_SAML2_ASSERTION(assertion) || ! provider_id)
		return FALSE;

	if (! assertion->Issuer || ! assertion->Issuer->content)
		return FALSE;

	return lasso_strisequal(assertion->Issuer->content,provider_id);
}

static gint
_lasso_saml20_login_decrypt_assertion(LassoLogin *login, LassoSamlp2Response *samlp2_response)
{
	GList *encryption_private_keys = NULL;
	GList *it = NULL;
	gboolean at_least_one_decryption_failture = FALSE;
	gboolean at_least_one_malformed_element = FALSE;

	if (! samlp2_response->EncryptedAssertion)
		return 0; /* nothing to do */

	encryption_private_keys = lasso_server_get_encryption_private_keys(login->parent.server);
	if (! encryption_private_keys) {
			message(G_LOG_LEVEL_WARNING, "Missing private encryption key, cannot decrypt assertions.");
			return LASSO_DS_ERROR_DECRYPTION_FAILED_MISSING_PRIVATE_KEY;
	}

	lasso_foreach (it, samlp2_response->EncryptedAssertion) {
		LassoSaml2EncryptedElement *encrypted_assertion;
		LassoSaml2Assertion * assertion = NULL;
		int rc1 = 0;

		if (! LASSO_IS_SAML2_ENCRYPTED_ELEMENT(it->data)) {
			message(G_LOG_LEVEL_WARNING, "EncryptedAssertion contains a non EncryptedElement object");
			at_least_one_malformed_element |= TRUE;
			continue;
		}
		encrypted_assertion = (LassoSaml2EncryptedElement*)it->data;
		lasso_foreach_full_begin(xmlSecKey*, encryption_private_key, it,
				encryption_private_keys)
		{
			rc1 = lasso_saml2_encrypted_element_decrypt(encrypted_assertion, encryption_private_key, (LassoNode**)&assertion);
			if (rc1 == 0)
				break;
		}
		lasso_foreach_full_end();
		if (rc1 == LASSO_DS_ERROR_DECRYPTION_FAILED) {
			message(G_LOG_LEVEL_WARNING, "Could not decrypt the EncryptedKey");
			at_least_one_decryption_failture |= TRUE;
			continue;
		} else if (rc1) {
			message(G_LOG_LEVEL_WARNING, "Could not decrypt an assertion: %s", lasso_strerror(rc1));
			at_least_one_decryption_failture |= TRUE;
			continue;
		}

		if (! LASSO_IS_SAML2_ASSERTION(assertion)) {
			message(G_LOG_LEVEL_WARNING, "EncryptedAssertion contains something that is not an assertion");
			lasso_release_gobject(assertion);
			continue;
		}
		/* copy the assertion to the clear assertion list */
		lasso_list_add_new_gobject(samlp2_response->Assertion, assertion);
	}
	
	if (at_least_one_decryption_failture) {
		return LASSO_DS_ERROR_DECRYPTION_FAILED;
	}
	if (at_least_one_malformed_element) {
		return LASSO_XML_ERROR_SCHEMA_INVALID_FRAGMENT;
	}
	return 0;
}

static gint
lasso_saml20_login_process_response_status_and_assertion(LassoLogin *login)
{
	LassoSamlp2StatusResponse *response;
	LassoSamlp2Response *samlp2_response = NULL;
	LassoProfile *profile;
	char *status_value;
	lasso_error_t rc = 0;
	lasso_error_t assertion_signature_status = 0;
	LassoProfileSignatureVerifyHint verify_hint;

	profile = &login->parent;
	lasso_extract_node_or_fail(response, profile->response, SAMLP2_STATUS_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(samlp2_response, response, SAMLP2_RESPONSE,
			LASSO_PROFILE_ERROR_INVALID_MSG);

	if (response->Status == NULL || ! LASSO_IS_SAMLP2_STATUS(response->Status) ||
			response->Status->StatusCode == NULL ||
			response->Status->StatusCode->Value == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}

	status_value = response->Status->StatusCode->Value;
	if (status_value && lasso_strisnotequal(status_value,LASSO_SAML2_STATUS_CODE_SUCCESS)) {
		if (lasso_strisequal(status_value,LASSO_SAML2_STATUS_CODE_REQUEST_DENIED))
			return LASSO_LOGIN_ERROR_REQUEST_DENIED;
		if (lasso_strisequal(status_value,LASSO_SAML2_STATUS_CODE_RESPONDER) ||
				lasso_strisequal(status_value,LASSO_SAML2_STATUS_CODE_REQUESTER)) {
			/* samlp:Responder */
			if (response->Status->StatusCode->StatusCode &&
					response->Status->StatusCode->StatusCode->Value) {
				status_value = response->Status->StatusCode->StatusCode->Value;
				if (lasso_strisequal(status_value,LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST)) {
					return LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
				}
				if (lasso_strisequal(status_value,LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL)) {
					return LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL;
				}
			}
		}
		return LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS;
	}

	/* Decrypt all EncryptedAssertions */
	_lasso_saml20_login_decrypt_assertion(login, samlp2_response);
	/* traverse all assertions */
	goto_cleanup_if_fail_with_rc (samlp2_response->Assertion != NULL,
			LASSO_PROFILE_ERROR_MISSING_ASSERTION);

	verify_hint = lasso_profile_get_signature_verify_hint(profile);

	lasso_foreach_full_begin(LassoSaml2Assertion*, assertion, it, samlp2_response->Assertion);
		LassoSaml2Subject *subject = NULL;

		lasso_assign_gobject (login->private_data->saml2_assertion, assertion);

		/* If signature has already been verified on the message, and assertion has the same
		 * issuer as the message, the assertion is covered. So no need to verify a second
		 * time */
		if (profile->signature_status != 0 
			|| ! _lasso_check_assertion_issuer(assertion,
				profile->remote_providerID)
			|| verify_hint == LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE) {
			assertion_signature_status = lasso_saml20_login_check_assertion_signature(login,
					assertion);
			/* If signature validation fails, it is the return code for this function */
			if (assertion_signature_status) {
				rc = LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE;
			}
		}

		lasso_extract_node_or_fail(subject, assertion->Subject, SAML2_SUBJECT,
				LASSO_PROFILE_ERROR_MISSING_SUBJECT);

		/* Verify Subject->SubjectConfirmationData->InResponseTo */
		if (login->private_data->request_id) {
			const char *in_response_to = lasso_saml2_assertion_get_in_response_to(assertion);

			if (lasso_strisnotequal(in_response_to,login->private_data->request_id)) {
				rc = LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID;
				goto cleanup;
			}
		}

		/** Handle nameid */
		lasso_check_good_rc(lasso_saml20_profile_process_name_identifier_decryption(profile,
					&subject->NameID, &subject->EncryptedID));
	lasso_foreach_full_end();

	switch (verify_hint) {
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE:
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE:
			break;
		case LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE:
			/* ignore signature errors */
			if (rc == LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE) {
				rc = 0;
			}
			break;
		default:
			g_assert(0);
	}
cleanup:
	return rc;
}


gint
lasso_saml20_login_accept_sso(LassoLogin *login)
{
	LassoProfile *profile;
	LassoSaml2Assertion *assertion;
	GList *previous_assertion_ids, *t;
	LassoSaml2NameID *ni;
	LassoFederation *federation;

	profile = LASSO_PROFILE(login);
	if (LASSO_SAMLP2_RESPONSE(profile->response)->Assertion == NULL)
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;

	assertion = LASSO_SAMLP2_RESPONSE(profile->response)->Assertion->data;
	if (assertion == NULL)
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;

	previous_assertion_ids = lasso_session_get_assertion_ids(profile->session,
			profile->remote_providerID);
	lasso_foreach(t, previous_assertion_ids) {
		if (lasso_strisequal(t->data, assertion->ID)) {
			lasso_release_list_of_strings(previous_assertion_ids);
			return LASSO_LOGIN_ERROR_ASSERTION_REPLAY;
		}
	}
	lasso_release_list_of_strings(previous_assertion_ids);

	lasso_session_add_assertion(profile->session, profile->remote_providerID,
			LASSO_NODE(assertion));

	if (assertion->Subject && assertion->Subject->NameID) {
		ni = assertion->Subject->NameID;
	} else {
		return LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER;
	}

	/* create federation, only if nameidentifier format is Federated */
	if (ni && ni->Format
			&& lasso_strisequal(ni->Format,LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT)) {
		federation = lasso_federation_new(LASSO_PROFILE(login)->remote_providerID);

		lasso_assign_gobject(federation->local_nameIdentifier, ni);
		/* add federation in identity */
		lasso_identity_add_federation(LASSO_PROFILE(login)->identity, federation);
	}

	return 0;
}

gint
lasso_saml20_login_build_authn_response_msg(LassoLogin *login)
{
	LassoProfile *profile;
	LassoProvider *remote_provider = NULL;
	LassoSaml2Assertion *assertion = NULL;
	LassoHttpMethod http_method = LASSO_HTTP_METHOD_NONE;
	char *url = NULL;
	int rc = 0;

	profile = &login->parent;

	if (login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST &&
		login->protocolProfile != LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE);
	}

	if (_lasso_login_must_sign_non_authn_request(login)) {
		lasso_check_good_rc(lasso_profile_saml20_setup_message_signature(profile,
					profile->response));
	} else {
		lasso_node_remove_signature(profile->response);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	url = lasso_saml20_login_get_assertion_consumer_service_url(login, remote_provider);

	assertion = login->private_data->saml2_assertion;
	if (LASSO_IS_SAML2_ASSERTION(assertion) && url) {
		LassoSaml2SubjectConfirmationData *subject_confirmation_data;

		subject_confirmation_data =
			lasso_saml2_assertion_get_subject_confirmation_data(assertion, TRUE);
		lasso_assign_string(subject_confirmation_data->Recipient, url);
	}

	/* If there is a non-encrypted NameID, fix the assertion in the session */
	if (assertion && assertion->Subject && assertion->Subject->NameID) {
		/* store assertion in session object */
		if (profile->session == NULL) {
			profile->session = lasso_session_new();
		}
		lasso_session_add_assertion(profile->session, profile->remote_providerID,
				LASSO_NODE(assertion));
	}

	switch (login->protocolProfile) {
		case LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST:
			http_method = LASSO_HTTP_METHOD_POST;
			break;
		case LASSO_LOGIN_PROTOCOL_PROFILE_REDIRECT:
			http_method = LASSO_HTTP_METHOD_REDIRECT;
			break;
		default:
			message(G_LOG_LEVEL_CRITICAL, "Cannot happen");
			break;
	}
	lasso_check_good_rc(lasso_saml20_profile_build_response_msg(profile, NULL, http_method, url));

cleanup:
	lasso_release_string(url);
	return rc;
}

static char*
lasso_saml20_login_get_assertion_consumer_service_url(LassoLogin *login,
	LassoProvider *remote_provider)
{
	LassoSamlp2AuthnRequest *request;
	char *url = NULL;

	request = LASSO_SAMLP2_AUTHN_REQUEST(LASSO_PROFILE(login)->request);

	if (request->AssertionConsumerServiceURL) {
		if (lasso_saml20_provider_check_assertion_consumer_service_url(remote_provider,
					request->AssertionConsumerServiceURL,
					request->ProtocolBinding)) {
			return g_strdup(request->AssertionConsumerServiceURL);
		}
	}

	if (request->AssertionConsumerServiceIndex != -1 || request->ProtocolBinding == NULL) {
		url = lasso_saml20_provider_get_assertion_consumer_service_url(remote_provider,
				request->AssertionConsumerServiceIndex);
	}

	if (url == NULL && request->ProtocolBinding) {
		url = lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(
				remote_provider, request->ProtocolBinding);
	}

	if (url == NULL) {
		message(G_LOG_LEVEL_WARNING,
				"can't find assertion consumer service url (going for default)");
		url = lasso_saml20_provider_get_assertion_consumer_service_url(remote_provider, -1);
	}

	return url;
}

gint
lasso_saml20_login_init_idp_initiated_authn_request(LassoLogin *login,
		const gchar *remote_providerID)
{
	LassoProfile *profile = NULL;
	LassoProvider *provider = NULL;
	LassoServer *server = NULL;
	gchar *default_name_id_format = NULL;
	int rc = 0;

	profile = &login->parent;
	lasso_extract_node_or_fail(server, lasso_profile_get_server(profile), SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	provider = lasso_server_get_provider(server, remote_providerID);
	if (! LASSO_IS_PROVIDER(provider))
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;

	/* fix roles */
	server->parent.role = LASSO_PROVIDER_ROLE_IDP;
	provider->role = LASSO_PROVIDER_ROLE_SP;

	lasso_assign_string(profile->remote_providerID, remote_providerID);
	lasso_assign_new_gobject(profile->request, lasso_samlp2_authn_request_new());
	lasso_assign_new_gobject(LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy,
			lasso_samlp2_name_id_policy_new());
	lasso_assign_new_gobject(LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Issuer,
			LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
					(char*)remote_providerID)));
	default_name_id_format = lasso_provider_get_default_name_id_format(provider);
	/* Change default NameIDFormat if default exists */
	if (default_name_id_format) {
		lasso_assign_new_string(LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy->Format,
				default_name_id_format);
	} else {
		/* we eventually used the default of the IDP (not of the target SP), so we reset to
		 * Lasso default, that is Transient */
		lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT);
	}
	lasso_assign_string(LASSO_SAMLP2_AUTHN_REQUEST(profile->request)->NameIDPolicy->SPNameQualifier,
		remote_providerID);
cleanup:

	return rc;
}
