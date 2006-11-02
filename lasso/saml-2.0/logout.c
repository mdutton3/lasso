/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/saml-2.0/logoutprivate.h>
#include <lasso/saml-2.0/profileprivate.h>
#include <lasso/saml-2.0/federationprivate.h>

#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/logout.h>
#include <lasso/id-ff/logoutprivate.h>
#include <lasso/id-ff/identityprivate.h>
#include <lasso/id-ff/sessionprivate.h>
#include <lasso/id-ff/profileprivate.h>

#include <lasso/xml/saml-2.0/samlp2_logout_request.h>
#include <lasso/xml/saml-2.0/samlp2_logout_response.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>

static void check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile);

int
lasso_saml20_logout_init_request(LassoLogout *logout, LassoProvider *remote_provider,
		LassoHttpMethod http_method)
{
	LassoProfile *profile = LASSO_PROFILE(logout);
	LassoNode *assertion_n, *name_id_n;
	LassoSaml2Assertion *assertion;
	LassoSaml2NameID *name_id;
	LassoFederation *federation;
	LassoSession *session;
	LassoSamlp2RequestAbstract *request;

	/* session existence has been checked in id-ff/ */
	session = lasso_profile_get_session(profile);

	assertion_n = lasso_session_get_assertion(session, profile->remote_providerID);
	if (LASSO_IS_SAML2_ASSERTION(assertion_n) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Assertion not found");
		return LASSO_ERROR_UNDEFINED;
	}

	assertion = LASSO_SAML2_ASSERTION(assertion_n);

	if (assertion->Subject == NULL) {
		return LASSO_ERROR_UNDEFINED;
	}

	name_id = assertion->Subject->NameID;
	if (name_id->Format && strcmp(name_id->Format,
				LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT) == 0) {
		if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
			return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
		}
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (federation == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		}

		name_id_n = lasso_profile_get_nameIdentifier(profile);
		if (name_id_n == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND);
		}
		if (federation->local_nameIdentifier) {
			profile->nameIdentifier = g_object_ref(federation->local_nameIdentifier);
		} else {
			profile->nameIdentifier = g_object_ref(name_id_n);
		}

	} else {
		profile->nameIdentifier = g_object_ref(name_id);
	}

	if (http_method == LASSO_HTTP_METHOD_ANY) {
		http_method = lasso_provider_get_first_http_method(
				LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT);
	} else {
		if (lasso_provider_accept_http_method(LASSO_PROVIDER(profile->server),
					remote_provider,
					LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT,
					http_method,
					TRUE) == FALSE) {
			if (http_method == LASSO_HTTP_METHOD_REDIRECT) {
				/* it was probably used as last resort, and
				 * failed, since the remote provider doesn't
				 * support any logout.  remove assertion
				 * unconditionnaly. */
				lasso_session_remove_assertion(profile->session,
						profile->remote_providerID);
				if (logout->initial_remote_providerID && logout->initial_request) {
					g_free(profile->remote_providerID);
					profile->remote_providerID = g_strdup(
							logout->initial_remote_providerID);
					/* XXX: create response
					profile->response = lasso_lib_logout_response_new_full(
						LASSO_PROVIDER(profile->server)->ProviderID,
						LASSO_SAML_STATUS_CODE_SUCCESS,
						LASSO_LIB_LOGOUT_REQUEST(logout->initial_request),
						LASSO_SIGNATURE_TYPE_NONE,
						0);
					*/
				}
			}
			return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	/* free profile->request if it was already set */
	if (LASSO_IS_NODE(profile->request)) {
		lasso_node_destroy(profile->request);
		profile->request = NULL;
	}

	profile->request = lasso_samlp2_logout_request_new();
	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	request->ID = lasso_build_unique_id(32);
	request->Version = g_strdup("2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	LASSO_SAMLP2_LOGOUT_REQUEST(request)->NameID = g_object_ref(profile->nameIdentifier);

	/* XXX: SessionIndex */

	logout->initial_http_request_method = http_method;

	return 0;
}


int
lasso_saml20_logout_build_request_msg(LassoLogout *logout, LassoProvider *remote_provider)
{
	LassoProfile *profile = LASSO_PROFILE(logout);

	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->private_key_file =
		g_strdup(profile->server->private_key);
	LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->certificate_file = 
		g_strdup(profile->server->certificate);

	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
				"SingleLogoutService SOAP");
		profile->msg_body = lasso_node_export_to_soap(profile->request);
		return 0;
	}
	
	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		char *url, *query;
		url = lasso_provider_get_metadata_one(remote_provider,
				"SingleLogoutService HTTP-Redirect");
		if (url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}
		query = lasso_node_export_to_query(profile->request,
					profile->server->signature_method,
					profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}
		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		return 0;
	}
	
	/* XXX: artifact support */

	return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
}

int
lasso_saml20_logout_process_request_msg(LassoLogout *logout, char *request_msg)
{
	LassoProfile *profile = LASSO_PROFILE(logout);
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	profile->request = lasso_samlp2_logout_request_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->request), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	if (profile->remote_providerID) {
		g_free(profile->remote_providerID);
	}

	profile->remote_providerID = g_strdup(
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Issuer->content);
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);

	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* verify signatures */
	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "ID", format);
	profile->signature_status = 0; /* XXX: signature check disabled for zxid */

	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;

	profile->nameIdentifier = g_object_ref(
			LASSO_SAMLP2_LOGOUT_REQUEST(profile->request)->NameID);

	return profile->signature_status;
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
	LassoFederation *federation;

	if (LASSO_IS_SAMLP2_LOGOUT_REQUEST(profile->request) == FALSE)
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;

	if (profile->remote_providerID) {
		g_free(profile->remote_providerID);
	}

	profile->remote_providerID = g_strdup(
			LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->Issuer->content);

	/* get the provider */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	if (profile->response) {
		lasso_node_destroy(profile->response);
	}

	profile->response = lasso_samlp2_logout_response_new();
	response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);
	response->ID = lasso_build_unique_id(32);
	response->Version = g_strdup("2.0");
	response->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	response->IssueInstant = lasso_get_current_time();
	response->InResponseTo = g_strdup(LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
	lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_SUCCESS);

	response->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (profile->server->certificate) {
		response->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		response->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	response->private_key_file = g_strdup(profile->server->private_key);
	response->certificate_file = g_strdup(profile->server->certificate);

	/* verify signature status */
	if (profile->signature_status != 0) {
		/* XXX: which SAML2 Status Code ? */
		lasso_saml20_profile_set_response_status(profile, 
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
		return profile->signature_status;
	}

	/* Get the name identifier */
	name_id = LASSO_SAMLP2_LOGOUT_REQUEST(profile->request)->NameID;
	if (name_id == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in logout request");
		/* XXX: which status code in SAML 2.0 ? */
		lasso_saml20_profile_set_response_status(
				profile, LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
	}

	if (profile->session == NULL) {
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return critical_error(LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	}

	/* verify authentication */
	assertion_n = lasso_session_get_assertion(profile->session, profile->remote_providerID);
	if (assertion_n == NULL) {
		message(G_LOG_LEVEL_WARNING, "%s has no assertion", profile->remote_providerID);
		lasso_saml20_profile_set_response_status(profile,
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);
		return LASSO_ERROR_UNDEFINED;
	}

	assertion = LASSO_SAML2_ASSERTION(assertion_n);

	/* If name identifier is federated, then verify federation */
	if (strcmp(name_id->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT) == 0) {
		if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
			/* XXX: which SAML 2 status code ? */
			lasso_saml20_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
		}
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (LASSO_IS_FEDERATION(federation) == FALSE) {
			/* XXX: which status code in SAML 2 ? */
			lasso_saml20_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		}

		if (lasso_federation_verify_name_identifier(federation,
					LASSO_NODE(name_id)) == FALSE) {
			message(G_LOG_LEVEL_WARNING, "No name identifier for %s",
					profile->remote_providerID);
			lasso_saml20_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return LASSO_ERROR_UNDEFINED;
		}
	}

	/* if SOAP request method at IDP then verify all the remote service providers support
	   SOAP protocol profile.
	   If one remote authenticated principal service provider doesn't support SOAP
	   then return UnsupportedProfile to original service provider */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {

		logout->private_data->all_soap = TRUE;
		g_hash_table_foreach(profile->server->providers,
				(GHFunc)check_soap_support, profile);

		if (logout->private_data->all_soap == FALSE) {
			lasso_saml20_profile_set_response_status(profile,
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
			g_hash_table_size(profile->session->assertions) >= 1) {
		logout->initial_remote_providerID = profile->remote_providerID;
		logout->initial_request = LASSO_NODE(profile->request);
		logout->initial_response = LASSO_NODE(profile->response);

		profile->remote_providerID = NULL;
		profile->request = NULL;
		profile->response = NULL;
	}

	return 0;


}

static void
check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile)
{
	GList *supported_profiles;
	LassoSaml2Assertion *assertion;
	LassoNode *assertion_n;

	if (strcmp(provider->ProviderID, profile->remote_providerID) == 0)
		return; /* original service provider (initiated logout) */

	assertion_n = lasso_session_get_assertion(profile->session, provider->ProviderID);
	if (assertion_n == NULL)
		return; /* not authenticated with this provider */
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
	LassoProvider *provider;
	char *url, *query;

	if (profile->response == NULL) {
		/* no response set here means request denied */
		profile->response = lasso_samlp2_logout_response_new();
		response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);
		response->ID = lasso_build_unique_id(32);
		response->Version = g_strdup("2.0");
		response->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
				LASSO_PROVIDER(profile->server)->ProviderID));
		response->IssueInstant = lasso_get_current_time();
		response->InResponseTo = g_strdup(
				LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request)->ID);
		lasso_saml20_profile_set_response_status(profile, 
				LASSO_SAML2_STATUS_CODE_REQUEST_DENIED);

		response->sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
		if (profile->server->certificate) {
			response->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
		} else {
			response->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
		}
		response->private_key_file = g_strdup(profile->server->private_key);
		response->certificate_file = g_strdup(profile->server->certificate);
	}

	if (profile->remote_providerID == NULL || profile->response == NULL) {
		/* no remote provider id set or no response set, this means
		 * this function got called before validate_request, probably
		 * because there were no active session */
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* build logout response message */
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->msg_url = NULL;
		profile->msg_body = lasso_node_export_to_soap(profile->response);
		return 0;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* get the provider */
		provider = g_hash_table_lookup(profile->server->providers,
				profile->remote_providerID);
		if (provider == NULL) {
			return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
		}

		url = lasso_provider_get_metadata_one(provider,
				"SingleLogoutService HTTP-Redirect ResponseLocation");
		if (url == NULL) {
			url = lasso_provider_get_metadata_one(provider,
					"SingleLogoutService HTTP-Redirect");
			if (url == NULL) {
				return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
			}
		}
		query = lasso_node_export_to_query(LASSO_NODE(profile->response),
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}
		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		profile->msg_body = NULL;
		g_free(url);
		g_free(query);
		return 0;
	}

	return LASSO_PROFILE_ERROR_MISSING_REQUEST;


}

int
lasso_saml20_process_response_msg(LassoLogout *logout, const char *response_msg)
{
	LassoProfile *profile = LASSO_PROFILE(logout);
	LassoHttpMethod response_method;
	LassoProvider *remote_provider;
	LassoSamlp2StatusResponse *response;
	LassoMessageFormat format;
	char *status_code_value;
	int rc;

	if (LASSO_IS_SAMLP2_LOGOUT_RESPONSE(profile->response) == TRUE) {
		lasso_node_destroy(profile->response);
		profile->response = NULL;
	}

	profile->response = lasso_samlp2_logout_response_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->response), response_msg);

	switch (format) {
		case LASSO_MESSAGE_FORMAT_SOAP:
			response_method = LASSO_HTTP_METHOD_SOAP;
			break;
		case LASSO_MESSAGE_FORMAT_QUERY:
			response_method = LASSO_HTTP_METHOD_REDIRECT;
			break;
		default:
			return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	profile->remote_providerID = g_strdup(
			LASSO_SAMLP2_STATUS_RESPONSE(profile->response)->Issuer->content);

	/* get the provider */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ID", format);
	if (rc == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		/* This message SHOULD be signed.
		 *  -- draft-liberty-idff-protocols-schema-1.2-errata-v2.0.pdf - p38
		 * XXX: is this also true for SAML 2.0?
		 */
		message(G_LOG_LEVEL_WARNING, "No signature on response");
		rc = 0;
	}

	response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);

	if (response->Status == NULL || response->Status->StatusCode == NULL
			|| response->Status->StatusCode->Value == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "No Status in LogoutResponse !");
		return LASSO_ERROR_UNDEFINED;
	}
	status_code_value = response->Status->StatusCode->Value;

	if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0) {
		/* If at SP, if the request method was a SOAP type, then
		 * rebuild the request message with HTTP method */
		/* XXX is this still what to do for SAML 2.0? */

		if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_REQUEST_DENIED) == 0) {
			/* assertion no longer on IdP so removing it locally
			 * too */
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);
			return LASSO_LOGOUT_ERROR_REQUEST_DENIED;
		}
		message(G_LOG_LEVEL_CRITICAL, "Status code is not success: %s", status_code_value);
		return LASSO_ERROR_UNDEFINED;
	}
	
	/* LogoutResponse status code value is ok */
	/* XXX: handle RelayState if necessary */

	/* if SOAP method or, if IDP provider type and HTTP Redirect,
	 * then remove assertion */
	if ( response_method == LASSO_HTTP_METHOD_SOAP ||
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
			g_hash_table_size(profile->session->assertions) == 0) {
		remote_provider = g_hash_table_lookup(profile->server->providers,
				logout->initial_remote_providerID);
		if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
			if (profile->remote_providerID != NULL)
				g_free(profile->remote_providerID);
			if (profile->request != NULL)
				lasso_node_destroy(LASSO_NODE(profile->request));
			if (profile->response != NULL)
				lasso_node_destroy(LASSO_NODE(profile->response));

			profile->remote_providerID = logout->initial_remote_providerID;
			profile->request = logout->initial_request;
			profile->response = logout->initial_response;

			logout->initial_remote_providerID = NULL;
			logout->initial_request = NULL;
			logout->initial_response = NULL;
		}
	}

	return rc;

}
