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

#include <lasso/xml/lib_authentication_statement.h>

#include <lasso/id-ff/logout.h>
#include <lasso/id-ff/logoutprivate.h>

#include <lasso/id-ff/profileprivate.h>
#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/sessionprivate.h>

#include <lasso/saml-2.0/logoutprivate.h>

static void check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile);

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_logout_build_request_msg:
 * @logout: a #LassoLogout
 * 
 * Builds the logout request message.
 *
 * It gets the HTTP method retrieved to send the request and:
 * <itemizedlist>
 * <listitem><para>
 *   if it is a SOAP method, then it builds the logout request SOAP message,
 *   sets the msg_body attribute, gets the single logout service url and sets
 *   @msg_url in the logout object.
 * </para></listitem>
 * <listitem><para>
 *   if it is a HTTP-Redirect method, then it builds the logout request QUERY
 *   message, builds the logout request url, sets @msg_url in the logout
 *   request url, sets @msg_body to NULL.
 * </para></listitem>
 * </itemizedlist>
 *
 * If private key and certificate are set in server object it will also signs
 * the message (either with X509 if SOAP or with a simple signature for query
 * strings).
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_logout_build_request_msg(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *url, *query;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);
	lasso_profile_clean_msg_info(profile);

	if (profile->remote_providerID == NULL) {
		/* this means lasso_logout_init_request was not called before */
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	/* get remote provider */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	IF_SAML2(profile) {
		return lasso_saml20_logout_build_request_msg(logout, remote_provider);
	}

	/* build the logout request message */
	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
		/* build the logout request message */
		profile->msg_url = lasso_provider_get_metadata_one(
				remote_provider, "SoapEndpoint");
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->private_key_file = 
			profile->server->private_key;
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->certificate_file = 
			profile->server->certificate;
		profile->msg_body = lasso_node_export_to_soap(profile->request);
		return 0;
	}

	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* build and optionally sign the logout request QUERY message */
		url = lasso_provider_get_metadata_one(remote_provider,
				"SingleLogoutServiceURL");
		if (url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}
		query = lasso_node_export_to_query(LASSO_NODE(profile->request),
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}
		/* build the msg_url */
		profile->msg_url = lasso_concat_url_query(url, query);
		g_free(url);
		g_free(query);
		profile->msg_body = NULL;
		return 0;
	}

	return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
}


/**
 * lasso_logout_build_response_msg:
 * @logout: a #LassoLogout
 * 
 * Builds the logout response message.
 *
 * It gets the request message method and:
 * <itemizedlist>
 * <listitem><para>
 *    if it is a SOAP method, then it builds the logout response SOAP message,
 *    sets the msg_body attribute, gets the single logout service return url
 *    and sets @msg_url in the logout object.
 * </para></listitem>
 * <listitem><para>
 *    if it is a HTTP-Redirect method, then it builds the logout response QUERY message,
 *    builds the logout response url, sets @msg_url with the logout response url,
 *    sets @msg_body to NULL
 * </para></listitem>
 * </itemizedlist>
 *
 * If private key and certificate are set in server object it will also signs
 * the message (either with X509 if SOAP or with a simple signature for query
 * strings).
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_logout_build_response_msg(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoProvider *provider;
	gchar *url, *query;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);
	lasso_profile_clean_msg_info(profile);

	IF_SAML2(profile) {
		return lasso_saml20_logout_build_response_msg(logout);
	}

	if (profile->response == NULL) {
		if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
			profile->response = lasso_lib_logout_response_new_full(
					LASSO_PROVIDER(profile->server)->ProviderID,
					LASSO_SAML_STATUS_CODE_REQUEST_DENIED,
					LASSO_LIB_LOGOUT_REQUEST(profile->request),
					profile->server->certificate ? 
					LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
					LASSO_SIGNATURE_METHOD_RSA_SHA1);
		}
		if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
			profile->response = lasso_lib_logout_response_new_full(
					LASSO_PROVIDER(profile->server)->ProviderID,
					LASSO_SAML_STATUS_CODE_REQUEST_DENIED,
					LASSO_LIB_LOGOUT_REQUEST(profile->request),
					LASSO_SIGNATURE_TYPE_NONE,
					0);
		}
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
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->private_key_file = 
			g_strdup(profile->server->private_key);
		LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->certificate_file = 
			profile->server->certificate;
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

		url = lasso_provider_get_metadata_one(provider, "SingleLogoutServiceReturnURL");
		if (url == NULL) {
			/* XXX: but wouldn't it be nice to provide a fallback msgUrl,
			 * something like the document root of the other site ? */
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}
		query = lasso_node_export_to_query(profile->response,
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}
		profile->msg_url = lasso_concat_url_query(url, query);
		profile->msg_body = NULL;
		g_free(url);
		g_free(query);
		return 0;
	}

	return LASSO_PROFILE_ERROR_MISSING_REQUEST;
}

/**
 * lasso_logout_destroy:
 * @logout: a #LassoLogout
 *
 * Destroys a logout object.
 **/
void
lasso_logout_destroy(LassoLogout *logout)
{
	g_object_unref(G_OBJECT(logout));
}

/**
 * lasso_logout_get_next_providerID:
 * @logout: a #LassoLogout
 * 
 * Returns the provider id from providerID_index in list of providerIDs in
 * principal session with the exception of initial service provider ID.
 *
 * Return value: a newly allocated string or NULL
 **/
gchar*
lasso_logout_get_next_providerID(LassoLogout *logout)
{
	LassoProfile *profile;
	gchar        *providerID;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);
	profile = LASSO_PROFILE(logout);

	g_return_val_if_fail(LASSO_IS_SESSION(profile->session), NULL);
	providerID = lasso_session_get_provider_index(
			profile->session, logout->providerID_index);
	logout->providerID_index++;
	/* if it is the provider id of the SP requester, then get the next */
	if (logout->initial_remote_providerID && providerID &&
			strcmp(providerID, logout->initial_remote_providerID) == 0) {
		providerID = lasso_session_get_provider_index(
				profile->session, logout->providerID_index);
		logout->providerID_index++;
	}

	return providerID;
}

/**
 * lasso_logout_init_request:
 * @logout: a #LassoLogout
 * @remote_providerID: the providerID of the identity provider.  If NULL the
 *     first identity provider is used.
 * @request_method: if set, then it get the protocol profile in metadata
 *     corresponding of this HTTP request method.
 *
 * Initializes a new SLO request.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_logout_init_request(LassoLogout *logout, char *remote_providerID,
		LassoHttpMethod http_method)
{
	LassoProfile      *profile;
	LassoProvider     *remote_provider;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoNode *assertion_n, *name_identifier_n;
	LassoSamlAssertion *assertion;
	LassoSamlSubjectStatementAbstract *subject_statement;
	LassoFederation   *federation = NULL;
	gboolean           is_http_redirect_get_method = FALSE;
	LassoSession *session;
	char *session_index = NULL;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	/* verify if session exists */
	session = lasso_profile_get_session(profile);
	if (session == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	}

	/* get the remote provider id
	   If remote_providerID is NULL, then get the first remote provider id in session */
	if (remote_providerID == NULL) {
		profile->remote_providerID = lasso_session_get_provider_index(session, 0);
	} else {
		profile->remote_providerID = g_strdup(remote_providerID);
	}
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	/* get the provider */
	remote_provider = g_hash_table_lookup(
			profile->server->providers, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	IF_SAML2(profile) {
		return lasso_saml20_logout_init_request(logout, remote_provider, http_method);
	}

	/* get assertion */
	assertion_n = lasso_session_get_assertion(session, profile->remote_providerID);
	if (LASSO_IS_SAML_ASSERTION(assertion_n) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_ASSERTION);
	}
	
	assertion = LASSO_SAML_ASSERTION(assertion_n);

	if (assertion->AuthenticationStatement && LASSO_IS_LIB_AUTHENTICATION_STATEMENT(
				assertion->AuthenticationStatement)) {
		LassoLibAuthenticationStatement *as = 
			LASSO_LIB_AUTHENTICATION_STATEMENT(assertion->AuthenticationStatement);
		if (as->SessionIndex)
			session_index = g_strdup(as->SessionIndex);
	}

	/* if format is one time, then get name identifier from assertion,
	   else get name identifier from federation */
	subject_statement = NULL;
	nameIdentifier = NULL;
	if (LASSO_IS_SAML_SUBJECT_STATEMENT_ABSTRACT(assertion->AuthenticationStatement)) {
		subject_statement = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
				assertion->AuthenticationStatement);
		if (subject_statement && subject_statement->Subject) {
			nameIdentifier = subject_statement->Subject->NameIdentifier;
		}
	}


	if (nameIdentifier && strcmp(nameIdentifier->Format,
				LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME) != 0) {
		if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
			return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
		}
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (federation == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		}

		name_identifier_n = lasso_profile_get_nameIdentifier(profile);
		if (name_identifier_n == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND);
		}
		nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(name_identifier_n);
		if (federation->local_nameIdentifier) {
			profile->nameIdentifier = g_object_ref(federation->local_nameIdentifier);
		} else {
			profile->nameIdentifier = g_object_ref(nameIdentifier);
		}
	} else {
		profile->nameIdentifier = g_object_ref(nameIdentifier);
	}

	/* get / verify http method */
	if (http_method == LASSO_HTTP_METHOD_ANY) {
		http_method = lasso_provider_get_first_http_method(
				LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT);
		/* XXX: check it found a valid http method */
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
					profile->response = lasso_lib_logout_response_new_full(
						LASSO_PROVIDER(profile->server)->ProviderID,
						LASSO_SAML_STATUS_CODE_SUCCESS,
						LASSO_LIB_LOGOUT_REQUEST(logout->initial_request),
						LASSO_SIGNATURE_TYPE_NONE,
						0);
				}
			}
			return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	/* before setting profile->request, verify it is not already set */
	if (LASSO_IS_LIB_LOGOUT_REQUEST(profile->request) == TRUE) {
		lasso_node_destroy(LASSO_NODE(profile->request));
		profile->request = NULL;
	}

	/* build a new request object from http method */
	if (http_method == LASSO_HTTP_METHOD_SOAP) {
		profile->request = lasso_lib_logout_request_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				profile->server->certificate ? 
					LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
				LASSO_SIGNATURE_METHOD_RSA_SHA1);
	} else { /* http_method == LASSO_HTTP_METHOD_REDIRECT */
		is_http_redirect_get_method = TRUE;
		profile->request = lasso_lib_logout_request_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_NONE,
				0);
	}

	if (lasso_provider_get_protocol_conformance(remote_provider) < LASSO_PROTOCOL_LIBERTY_1_2) {
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MajorVersion = 1;
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MinorVersion = 1;
	}

	if (session_index)
		LASSO_LIB_LOGOUT_REQUEST(profile->request)->SessionIndex = session_index;
	if (profile->msg_relayState)
		LASSO_LIB_LOGOUT_REQUEST(profile->request)->RelayState =
			g_strdup(profile->msg_relayState);

	/* if logout request from a SP and if an HTTP Redirect/GET method, then remove assertion */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP && is_http_redirect_get_method) {
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);
	}

	/* Save the http method */
	logout->initial_http_request_method = http_method;

	return 0;
}

/**
 * lasso_logout_process_request_msg:
 * @logout: a #LassoLogout
 * @request_msg: the logout request message
 * 
 * Processes a SLO LogoutRequest message.  Rebuilds a request object from the
 * message and optionally verifies its signature.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_logout_process_request_msg(LassoLogout *logout, char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(logout);

	IF_SAML2(profile) {
		return lasso_saml20_logout_process_request_msg(logout, request_msg);
	}

	profile->request = lasso_lib_logout_request_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->request), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	if (profile->remote_providerID) {
		g_free(profile->remote_providerID);
	}

	profile->remote_providerID = g_strdup(
			LASSO_LIB_LOGOUT_REQUEST(profile->request)->ProviderID);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* verify signatures */
	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "RequestID", format);

	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;

	profile->nameIdentifier = g_object_ref(
			LASSO_LIB_LOGOUT_REQUEST(profile->request)->NameIdentifier);

	return profile->signature_status;
}


/**
 * lasso_logout_process_response_msg:
 * @logout: a #LassoLogout
 * @response_msg: the response message
 * 
 * Parses the response message and builds the response object.
 *
 * Checks the status code value and if it is not success, then if the local
 * provider is a Service Provider and response method is SOAP, then builds a
 * new logout request message for HTTP Redirect / GET method and returns the
 * error code LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE.
 *
 * If it is a SOAP method or, IDP type and http method is Redirect/GET,
 * then removes assertion.
 * 
 * If local server is an Identity Provider and if there is no more assertion
 * (Identity Provider has logged out every Service Providers), then restores
 * the initial response.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_logout_process_response_msg(LassoLogout *logout, gchar *response_msg)
{
	LassoProfile  *profile;
	LassoProvider *remote_provider;
	char *statusCodeValue;
	LassoHttpMethod response_method;
	LassoMessageFormat format;
	LassoLibStatusResponse *response;
	int rc;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(logout);

	IF_SAML2(profile) {
		return lasso_saml20_logout_process_response_msg(logout, response_msg);
	}

	/* before verify if profile->response is set */
	if (LASSO_IS_LIB_LOGOUT_RESPONSE(profile->response) == TRUE) {
		lasso_node_destroy(profile->response);
		profile->response = NULL;
	}

	profile->response = lasso_lib_logout_response_new();
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

	/* get provider */
	profile->remote_providerID = g_strdup(
			LASSO_LIB_STATUS_RESPONSE(profile->response)->ProviderID);
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ResponseID", format);
	if (rc == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		/* This message SHOULD be signed.
		 *  -- draft-liberty-idff-protocols-schema-1.2-errata-v2.0.pdf - p38
		 */
		message(G_LOG_LEVEL_WARNING, "No signature on response");
		rc = 0;
	}

	response = LASSO_LIB_STATUS_RESPONSE(profile->response);

	if (response->Status == NULL || response->Status->StatusCode == NULL
			|| response->Status->StatusCode->Value == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	}
	statusCodeValue = response->Status->StatusCode->Value;

	if (strcmp(statusCodeValue, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		/* At SP, if the request method was a SOAP type, then rebuild the request
		 * message with HTTP method */

		/* takes lower-level StatusCode if available */
		if (response->Status->StatusCode && response->Status->StatusCode->StatusCode)
			statusCodeValue = response->Status->StatusCode->StatusCode->Value;

		if (strcmp(statusCodeValue, LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE) == 0 &&
				remote_provider->role == LASSO_PROVIDER_ROLE_IDP &&
				logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
			gchar *url, *query;

			/* Build and optionally sign the logout request QUERY message */
			url = lasso_provider_get_metadata_one(remote_provider,
					"SingleLogoutServiceURL");
			if (url == NULL) {
				return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
			}
			query = lasso_node_export_to_query(LASSO_NODE(profile->request),
					profile->server->signature_method,
					profile->server->private_key);
			if (query == NULL) {
				g_free(url);
				return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
			}
			profile->msg_url = lasso_concat_url_query(url, query);
			g_free(url);
			g_free(query);
			profile->msg_body = NULL;

			/* send a HTTP Redirect / GET method, so first remove session */
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);

			return LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
		}
		if (strcmp(statusCodeValue, LASSO_SAML_STATUS_CODE_REQUEST_DENIED) == 0) {
			/* assertion no longer on idp so removing it locally too */
			message(G_LOG_LEVEL_WARNING, "SP answer is request denied");
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);
			return LASSO_LOGOUT_ERROR_REQUEST_DENIED;
		}
		if (strcmp(statusCodeValue,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST) == 0) {
			/* how could this happen ?  probably error in SP */
			/* let's remove the assertion nevertheless */
			message(G_LOG_LEVEL_WARNING, "SP answer is federation does not exist");
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);
			return LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND;
		}
		message(G_LOG_LEVEL_CRITICAL, "Status code is not success : %s", statusCodeValue);
		return LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;
	}

	/* LogoutResponse status code value is ok */

	/* set the msg_relayState */
	profile->msg_relayState = g_strdup(
			LASSO_LIB_STATUS_RESPONSE(profile->response)->RelayState);

	/* if SOAP method or, if IDP provider type and HTTP Redirect, then remove assertion */
	if ( response_method == LASSO_HTTP_METHOD_SOAP ||
			(remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			 response_method == LASSO_HTTP_METHOD_REDIRECT) ) {
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);
#if 0 /* ? */
		if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
				logout->providerID_index >= 0) {
			logout->providerID_index--;
		}
#endif
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


/**
 * lasso_logout_reset_providerID_index:
 * @logout: a #LassoLogout
 * 
 * Reset the providerID_index attribute (set to 0).
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint lasso_logout_reset_providerID_index(LassoLogout *logout)
{
	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	lasso_session_init_provider_ids(LASSO_PROFILE(logout)->session);
	logout->providerID_index = 0;
	return 0;
}

/**
 * lasso_logout_validate_request:
 * @logout: a #LassoLogout
 * 
 * <itemizedlist>
 * <listitem>
 *   Sets the remote provider id
 * </listitem><listitem>
 *   Sets a logout response with status code value to success.
 * </listitem><listitem>
 *   Verifies federation and authentication.
 * </listitem><listitem>
 *   If the request http method is a SOAP method, then verifies every other
 *   Service Providers supports SOAP method : if not, then sets status code
 *   value to UnsupportedProfile and returns a code error with
 *   LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE.
 * </listitem><listitem>
 *   Every tests are ok, then removes assertion.
 * </listitem><listitem>
 *   If local server is an Identity Provider and if there is more than one
 *   Service Provider (except the initial Service Provider), then saves the
 *   initial request, response and remote provider id.
 * </listitem>
 * </itemizedlist>
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_logout_validate_request(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoFederation *federation = NULL;
	LassoProvider *remote_provider;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoSamlAssertion *assertion;
	LassoNode *assertion_n;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	IF_SAML2(profile) {
		return lasso_saml20_logout_validate_request(logout);
	}

	/* verify logout request */
	if (LASSO_IS_LIB_LOGOUT_REQUEST(profile->request) == FALSE)
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;

	if (profile->remote_providerID) {
		g_free(profile->remote_providerID);
	}

	profile->remote_providerID = g_strdup(
			LASSO_LIB_LOGOUT_REQUEST(profile->request)->ProviderID);

	/* get the provider */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* Set LogoutResponse */
	profile->response = NULL;
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->response = lasso_lib_logout_response_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML_STATUS_CODE_SUCCESS,
				LASSO_LIB_LOGOUT_REQUEST(profile->request),
				profile->server->certificate ? 
					LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
				LASSO_SIGNATURE_METHOD_RSA_SHA1);
	}
	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		profile->response = lasso_lib_logout_response_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML_STATUS_CODE_SUCCESS,
				LASSO_LIB_LOGOUT_REQUEST(profile->request),
				LASSO_SIGNATURE_TYPE_NONE,
				0);
	}
	if (LASSO_IS_LIB_LOGOUT_RESPONSE(profile->response) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED);
	}

	/* verify signature status */
	if (profile->signature_status != 0) {
		lasso_profile_set_response_status(profile, 
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
	}

	/* Get the name identifier */
	nameIdentifier = LASSO_LIB_LOGOUT_REQUEST(profile->request)->NameIdentifier;
	if (nameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in logout request");
		lasso_profile_set_response_status(
				profile, LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
	}

	if (profile->session == NULL) {
		lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		return critical_error(LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	}

	/* verify authentication */
	assertion_n = lasso_session_get_assertion(profile->session, profile->remote_providerID);
	if (LASSO_IS_SAML_ASSERTION(assertion_n) == FALSE) {
		message(G_LOG_LEVEL_WARNING, "%s has no assertion", profile->remote_providerID);
		lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;
	}

	assertion = LASSO_SAML_ASSERTION(assertion_n);

	/* If name identifier is federated, then verify federation */
	if (strcmp(nameIdentifier->Format, LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED) == 0) {
		if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
		}
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (LASSO_IS_FEDERATION(federation) == FALSE) {
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		}

		if (lasso_federation_verify_name_identifier(federation,
					LASSO_NODE(nameIdentifier)) == FALSE) {
			message(G_LOG_LEVEL_WARNING, "No name identifier for %s",
					profile->remote_providerID);
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND;
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
			lasso_profile_set_response_status(profile,
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



/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "InitialRequest", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoLogout, initial_request) },
	{ "InitialResponse", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoLogout, initial_response) },
	{ "InitialRemoteProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLogout, initial_remote_providerID) },
	{ "InitialHttpRequestMethod", SNIPPET_CONTENT | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoLogout, initial_http_request_method) },
	/* "ProviderIdIndex" must not be dumped (since apps assume to get
	 * it back to 0 after a restore from dump) (maybe this behaviour should
	 * be fixed)
	 */
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static void
check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile)
{
	GList *supported_profiles;
	LassoSamlAssertion *assertion;
	LassoNode *assertion_n;

	if (strcmp(provider->ProviderID, profile->remote_providerID) == 0)
		return; /* original service provider (initiated logout) */

	assertion_n = lasso_session_get_assertion(profile->session, provider->ProviderID);
	if (LASSO_IS_SAML_ASSERTION(assertion_n) == FALSE) {
		return; /* not authenticated with this provider */
	}
	assertion = LASSO_SAML_ASSERTION(assertion_n);

	supported_profiles = lasso_provider_get_metadata_list(provider,
			"SingleLogoutProtocolProfile");
	while (supported_profiles && strcmp(supported_profiles->data,
				LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP) != 0)
		supported_profiles = g_list_next(supported_profiles);

	if (supported_profiles)
		return; /* provider support profile */

	
	LASSO_LOGOUT(profile)->private_data->all_soap = FALSE;
}


static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)"Logout");
	xmlSetProp(xmlnode, (xmlChar*)"LogoutDumpVersion", (xmlChar*)"2");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	return parent_class->init_from_xml(node, xmlnode);
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoLogout *logout = LASSO_LOGOUT(object);
	if (logout->private_data->dispose_has_run) {
		return;
	}
	logout->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{  
	LassoLogout *logout = LASSO_LOGOUT(object);
	g_free(logout->private_data);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLogout *logout)
{
	logout->private_data = g_new(LassoLogoutPrivate, 1);
	logout->private_data->dispose_has_run = FALSE;

	logout->initial_request = NULL;
	logout->initial_response = NULL;
	logout->initial_remote_providerID = NULL;

	logout->providerID_index = 0;
}

static void
class_init(LassoLogoutClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Logout");
	lasso_node_class_add_snippets(nclass, schema_snippets);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_logout_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLogoutClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLogout),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoLogout", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_logout_new:
 * @server: the #LassoServer
 * 
 * Creates a new #LassoLogout.
 * 
 * Return value: a newly created #LassoLogout object; or NULL if an error
 *     occured
 **/
LassoLogout*
lasso_logout_new(LassoServer *server)
{
	LassoLogout *logout;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	logout = g_object_new(LASSO_TYPE_LOGOUT, NULL);
	LASSO_PROFILE(logout)->server = g_object_ref(server);

	return logout;
}

/**
 * lasso_logout_new_from_dump:
 * @server: the #LassoServer
 * @dump: XML logout dump
 *
 * Restores the @dump to a new #LassoLogout.
 *
 * Return value: a newly created #LassoLogout; or NULL if an error occured
 **/
LassoLogout*
lasso_logout_new_from_dump(LassoServer *server, const char *dump)
{
	LassoLogout *logout;
	xmlDoc *doc;

	if (dump == NULL)
		return NULL;

	logout = lasso_logout_new(g_object_ref(server));
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(logout), xmlDocGetRootElement(doc)); 
	xmlFreeDoc(doc);

	return logout;
}

/**
 * lasso_logout_dump:
 * @logout: a #LassoLogout
 *
 * Dumps @logout content to an XML string.
 *
 * Return value: the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_logout_dump(LassoLogout *logout)
{
	return lasso_node_dump(LASSO_NODE(logout));
}
