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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../xml/private.h"
#include "providerprivate.h"
#include "logoutprivate.h"
#include "profileprivate.h"
#include "federationprivate.h"

#include "../id-ff/providerprivate.h"
#include "../id-ff/logout.h"
#include "../id-ff/logoutprivate.h"
#include "../id-ff/sessionprivate.h"
#include "../id-ff/profileprivate.h"
#include "../id-ff/serverprivate.h"

#include "../xml/xml_enc.h"

#include "../xml/saml-2.0/samlp2_logout_request.h"
#include "../xml/saml-2.0/samlp2_logout_response.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/saml2_authn_statement.h"
#include "../utils.h"

static void check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile);

static char*
_lasso_saml2_assertion_get_session_index(LassoSaml2Assertion *assertion)
{
	if (! LASSO_IS_SAML2_AUTHN_STATEMENT(assertion->AuthnStatement->data))
		return NULL;
	return((LassoSaml2AuthnStatement*)assertion->AuthnStatement->data)->SessionIndex;
}

int
lasso_saml20_logout_init_request(LassoLogout *logout, LassoProvider *remote_provider,
		LassoHttpMethod http_method)
{
	LassoProfile *profile = &logout->parent;
	LassoNode *assertion_n = NULL;
	LassoSaml2Assertion *assertion = NULL;
	//LassoSaml2NameID *name_id = NULL;
	LassoSession *session = NULL;
	//LassoSamlp2RequestAbstract *request = NULL;
	//LassoSaml2EncryptedElement *encrypted_element = NULL;
	LassoSamlp2LogoutRequest *logout_request = NULL;
	//char *assertion_SessionIndex = NULL;
	int rc = 0;

	logout_request = (LassoSamlp2LogoutRequest*) lasso_samlp2_logout_request_new();

	lasso_check_good_rc(lasso_saml20_init_request(profile,
			remote_provider->ProviderID,
			FALSE,
			&logout_request->parent,
			http_method,
			LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT));

	/* session existence has been checked in id-ff/ */
	session = lasso_profile_get_session(profile);
	assertion_n = lasso_session_get_assertion(session, profile->remote_providerID);
	if (LASSO_IS_SAML2_ASSERTION(assertion_n) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_ASSERTION);
	}
	lasso_ref(assertion_n);
	assertion = (LassoSaml2Assertion*)assertion_n;

	/* set the nameid */
	lasso_assign_gobject(logout_request->NameID, profile->nameIdentifier);
	/* Encrypt NameID */
	rc = lasso_saml20_profile_setup_encrypted_node(remote_provider, (LassoNode**)&logout_request->NameID,
			(LassoNode**)&logout_request->EncryptedID);
	/* set the session index if one is found */
	lasso_assign_string(logout_request->SessionIndex,
			_lasso_saml2_assertion_get_session_index(assertion));
	lasso_session_remove_assertion(profile->session,
				profile->remote_providerID);

cleanup:
	/* special case: we suppose REDIRECT is the last resort method, so we force assertion
	 * removal and create a possible response message with a second level status of PARTIAL. */
	if (rc == LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE
			&& http_method == LASSO_HTTP_METHOD_REDIRECT) {
		lasso_session_remove_assertion(profile->session,
				profile->remote_providerID);
		if (logout->initial_remote_providerID && logout->initial_request) {
			LassoSamlp2StatusResponse *response;

			logout->private_data->partial_logout = TRUE;
			lasso_assign_string(profile->remote_providerID,
					logout->initial_remote_providerID);
			response = (LassoSamlp2StatusResponse*) lasso_samlp2_logout_response_new();
			/* ignore return code */
			lasso_saml20_profile_init_response(profile, response, LASSO_SAML2_STATUS_CODE_SUCCESS,
					LASSO_SAML2_STATUS_CODE_PARTIAL_LOGOUT);
			lasso_release_gobject(response);
		}
	}
	lasso_release_gobject(logout_request);
	lasso_release_gobject(assertion_n);
	return rc;
}

int
lasso_saml20_logout_build_request_msg(LassoLogout *logout)
{
	LassoProfile *profile = &logout->parent;

	return lasso_saml20_profile_build_request_msg(profile, "SingleLogoutService",
			logout->parent.http_request_method, NULL);
}

int
lasso_saml20_logout_process_request_msg(LassoLogout *logout, char *request_msg)
{
	LassoProfile *profile = NULL;
	LassoSamlp2LogoutRequest *logout_request = NULL;
	int rc1 = 0, rc2 = 0;

	lasso_bad_param(LOGOUT, logout);
	lasso_null_param(request_msg);

	profile = LASSO_PROFILE(logout);
	logout_request = (LassoSamlp2LogoutRequest*) lasso_samlp2_logout_request_new();
	rc1 = lasso_saml20_profile_process_any_request(profile, (LassoNode*)logout_request,
			request_msg);

	logout_request = (LassoSamlp2LogoutRequest*)profile->request;
	if (rc1 && ! logout_request) {
		return rc1;
	}
	/* remember initial request method, for setting it for generating response */
	logout->initial_http_request_method = profile->http_request_method;

	rc2 = lasso_saml20_profile_process_name_identifier_decryption(profile,
			&logout_request->NameID,
			&logout_request->EncryptedID);

	lasso_release_gobject(logout_request);
	if (profile->signature_status) {
		return profile->signature_status;
	}
	if (rc1) {
		return rc1;
	}
	return rc2;
}

int
lasso_saml20_logout_validate_request(LassoLogout *logout)
{
	LassoProfile *profile = LASSO_PROFILE(logout);
	LassoProvider *remote_provider;
	LassoSamlp2StatusResponse *response;
	LassoSaml2NameID *name_id;
	LassoNode *assertion_n;
	LassoSaml2Assertion *assertion;
	LassoSamlp2LogoutRequest *logout_request;
	char *assertion_SessionIndex = NULL;
	int rc = 0;

	if (LASSO_IS_SAMLP2_LOGOUT_REQUEST(profile->request) == FALSE)
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	logout_request = (LassoSamlp2LogoutRequest*)profile->request;

	/* check the issuer */
	lasso_assign_string(profile->remote_providerID,
			logout_request->parent.Issuer->content);
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* create the response */
	response = (LassoSamlp2StatusResponse*)lasso_samlp2_logout_response_new();
	lasso_check_good_rc(lasso_saml20_profile_init_response(profile, response,
				LASSO_SAML2_STATUS_CODE_SUCCESS, NULL));

	/* verify signature status */
	if (profile->signature_status != 0) {
		lasso_saml20_profile_set_response_status_requester(profile,
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
		return profile->signature_status;
	}

	/* Get the name identifier */
	name_id = LASSO_SAMLP2_LOGOUT_REQUEST(profile->request)->NameID;
	if (name_id == NULL) {
		lasso_saml20_profile_set_response_status_responder(
				profile, LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
	}

	if (profile->session == NULL) {
		lasso_saml20_profile_set_response_status_responder(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return critical_error(LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	}

	/* verify authentication */
	assertion_n = lasso_session_get_assertion(profile->session, profile->remote_providerID);
	if (LASSO_IS_SAML2_ASSERTION(assertion_n) == FALSE) {
		lasso_saml20_profile_set_response_status_responder(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;
	}
	assertion = LASSO_SAML2_ASSERTION(assertion_n);

	/* Verify name identifier and session matching */
	if (assertion->Subject == NULL) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_RESPONDER,
				"http://lasso.entrouvert.org/error/MalformedAssertion");
		return LASSO_PROFILE_ERROR_MISSING_SUBJECT;
	}

	if (lasso_saml2_name_id_equals(name_id, assertion->Subject->NameID) != TRUE) {
		lasso_saml20_profile_set_response_status_responder(profile,
				LASSO_SAML2_STATUS_CODE_UNKNOWN_PRINCIPAL);
		return LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL;
	}

	/* verify session index */
	if (assertion->AuthnStatement) {
		if (! LASSO_IS_SAML2_AUTHN_STATEMENT(assertion->AuthnStatement->data)) {

			lasso_saml20_profile_set_response_status(profile,
					LASSO_SAML2_STATUS_CODE_RESPONDER, "http://lasso.entrouvert.org/error/MalformedAssertion");
			return LASSO_PROFILE_ERROR_BAD_SESSION_DUMP;
		}
		assertion_SessionIndex =
			((LassoSaml2AuthnStatement*)assertion->AuthnStatement->data)->SessionIndex;
		if (g_strcmp0(logout_request->SessionIndex, assertion_SessionIndex) != 0) {
			lasso_saml20_profile_set_response_status_responder(profile,
					LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
			return LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL;
		}
	}

	/* if SOAP request method at IDP then verify all the remote service providers support
	   SOAP protocol profile.  If one remote authenticated principal service provider doesn't
	   support SOAP then return UnsupportedProfile to original service provider */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {

		logout->private_data->all_soap = TRUE;
		g_hash_table_foreach(profile->server->providers,
				(GHFunc)check_soap_support, profile);

		if (logout->private_data->all_soap == FALSE) {
			lasso_saml20_profile_set_response_status_responder(profile,
					LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE);
			return LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	/* authentication is ok, federation is ok, propagation support is ok, remove assertion */
	lasso_session_remove_assertion(profile->session, profile->remote_providerID);

	/* if at IDP and nb sp logged > 1, then backup remote provider id,
	 * request and response
	 */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			lasso_session_count_assertions(profile->session) >= 1) {
		lasso_transfer_string(logout->initial_remote_providerID,
				profile->remote_providerID);
		lasso_transfer_gobject(logout->initial_request, profile->request);
		lasso_transfer_gobject(logout->initial_response, profile->response);
	}

cleanup:
	lasso_release_gobject(response);
	return rc;
}

static void
check_soap_support(G_GNUC_UNUSED gchar *key, LassoProvider *provider, LassoProfile *profile)
{
	const GList *supported_profiles;
	LassoSaml2Assertion *assertion;
	LassoNode *assertion_n;

	if (strcmp(provider->ProviderID, profile->remote_providerID) == 0)
		return; /* original service provider (initiated logout) */

	assertion_n = lasso_session_get_assertion(profile->session, provider->ProviderID);
	if (LASSO_IS_SAML2_ASSERTION(assertion_n) == FALSE) {
		return; /* not authenticated with this provider */
	}

	assertion = LASSO_SAML2_ASSERTION(assertion_n);

	supported_profiles = lasso_provider_get_metadata_list(provider,
			"SingleLogoutService SOAP");

	if (supported_profiles)
		return; /* provider support profile */

	LASSO_LOGOUT(profile)->private_data->all_soap = FALSE;
}

int
lasso_saml20_logout_build_response_msg(LassoLogout *logout)
{
	LassoProfile *profile = LASSO_PROFILE(logout);
	LassoSamlp2StatusResponse *response;
	int rc = 0;

	if (profile->response == NULL) {
		/* no response set here means request denied */
		response = (LassoSamlp2StatusResponse*) lasso_samlp2_logout_response_new();
		lasso_check_good_rc(lasso_saml20_profile_init_response(profile, response,
					LASSO_SAML2_STATUS_CODE_RESPONDER,
					LASSO_SAML2_STATUS_CODE_REQUEST_DENIED));
	}

	/* build logout response message */
	/* FIXME: should allow to override default response method, should just match that
	 * request/response are of the same type synchronous or asynchronous */
	rc = lasso_saml20_profile_build_response_msg(profile, "SingleLogoutService",
			logout->initial_http_request_method, NULL);

cleanup:
	lasso_release_gobject(response);
	return rc;
}

int
lasso_saml20_logout_process_response_msg(LassoLogout *logout, const char *response_msg)
{
	LassoProfile *profile = &logout->parent;
	LassoHttpMethod response_method;
	LassoProvider *remote_provider = NULL;
	LassoSamlp2StatusResponse *response = NULL;
	char *status_code_value = NULL;
	int rc = 0;

	response = (LassoSamlp2StatusResponse*)profile->response;
	lasso_check_good_rc(lasso_saml20_profile_process_any_response(profile, response, &response_method, response_msg));

	status_code_value = response->Status->StatusCode->Value;
	if (status_code_value && strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0) {
		/* If at SP, if the request method was a SOAP type, then
		 * rebuild the request message with HTTP method */
		/* XXX is this still what to do for SAML 2.0? */
		logout->private_data->partial_logout = TRUE;

		if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_RESPONDER) == 0) {
			/* Responder -> look inside */
			if (response->Status->StatusCode->StatusCode) {
				status_code_value = response->Status->StatusCode->StatusCode->Value;
			}
			if (status_code_value == NULL) {
				rc = LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
				goto cleanup;
			}
		}
		if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_REQUEST_DENIED) == 0) {
			/* assertion no longer on IdP so removing it locally
			 * too */
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);
			rc = LASSO_LOGOUT_ERROR_REQUEST_DENIED;
			goto cleanup;
		}
		if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_UNKNOWN_PRINCIPAL) == 0) {
			rc = LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL;
			goto cleanup;
		}
		rc = LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;
		goto cleanup;
	}


	/* if SOAP method or, if IDP provider type and HTTP Redirect,
	 * then remove assertion */
	if (response_method == LASSO_HTTP_METHOD_SOAP ||
			(remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			 response_method == LASSO_HTTP_METHOD_REDIRECT) ) {
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);
	}

	/* If at IDP and if there is no more assertion, IDP has logged out
	 * every SPs, return the initial response to initial SP.  Caution: We
	 * can't use the test (remote_provider->role == LASSO_PROVIDER_ROLE_SP)
	 * to know whether the server is acting as an IDP or a SP, because it
	 * can be a proxy. So we have to use the role of the initial remote
	 * provider instead.
	 */
	if (logout->initial_remote_providerID &&
			lasso_session_count_assertions(profile->session) == 0) {
		remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (remote_provider->role & LASSO_PROVIDER_ROLE_SP) {
			lasso_transfer_string(profile->remote_providerID,
					logout->initial_remote_providerID);
			lasso_transfer_gobject(profile->request, logout->initial_request);
			lasso_transfer_gobject(profile->response, logout->initial_response);
			/* if some of the logout failed, set a partial logout status code */
			if (logout->private_data->partial_logout) {
				/* reset the partial logout status */
				logout->private_data->partial_logout = FALSE;
				lasso_saml20_profile_set_response_status(profile,
						LASSO_SAML2_STATUS_CODE_SUCCESS,
						LASSO_SAML2_STATUS_CODE_PARTIAL_LOGOUT);
			}
		}
	}

	/* if at SP */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP &&
			response_method == LASSO_HTTP_METHOD_REDIRECT) {
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);
	}

cleanup:
	lasso_release_gobject(response);
	return rc;

}
