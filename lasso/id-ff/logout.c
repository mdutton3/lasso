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

#include <lasso/environs/logout.h>
#include <lasso/xml/errors.h>

struct _LassoLogoutPrivate
{
	gboolean dispose_has_run;
	gboolean all_soap;
};

static void check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile);

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_logout_build_request_msg:
 * @logout: the logout object
 * 
 * This method builds the logout request message.
 *
 * It gets the http method retrieved to send the request and :
 *
 * - if it is a SOAP method, then it builds the logout request SOAP message,
 *   sets the msg_body attribute, gets the single logout service url and sets
 *   the msg_url attribute of the logout object.
 *
 * - if it is a HTTP-Redirect method, then it builds the logout request QUERY
 *   message, builds the logout request url, sets the msg_url to the logout
 *   request url, sets the msg_body to NULL
 *
 * Optionaly (if private key and certificates paths are set in server object)
 * it signs the message (with X509 if a SOAP message, else with simple
 * signature if a QUERY message)
 * 
 * Return value: 0 if ok, else return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD
 * if the http method is invalid, else returns -1
 **/
gint
lasso_logout_build_request_msg(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *url, *query;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	/* get remote provider */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return -1;
	}

	/* build the logout request message */
	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
		/* build the logout request message */
		profile->msg_url = lasso_provider_get_metadata_one(remote_provider, "SoapEndpoint");
		profile->msg_body = lasso_node_export_to_soap(profile->request,
				profile->server->private_key, profile->server->certificate);
		return 0;
	}

	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* build and optionaly sign the logout request QUERY message */
		url = lasso_provider_get_metadata_one(remote_provider,
				"SingleLogoutServiceURL");
		if (url == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Unknown profile service URL");
			return -1;
		}
		query = lasso_node_export_to_query(profile->request,
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			message(G_LOG_LEVEL_CRITICAL, "Error while building request QUERY url");
			return -1;
		}
		/* build the msg_url */
		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		g_free(url);
		g_free(query);
		profile->msg_body = NULL;
		return 0;
	}

	message(G_LOG_LEVEL_CRITICAL, "Invalid http method");
	return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
}


/**
 * lasso_logout_build_response_msg:
 * @logout: the logout object
 * 
 * This method builds the logout response message.
 *
 * It gets the request message method and :
 *    if it is a SOAP method, then it builds the logout response SOAP message,
 *    sets the msg_body attribute, gets the single logout service return url
 *    and sets the msg_url attribute of the logout object.
 *
 *    if it is a HTTP-Redirect method, then it builds the logout response QUERY message,
 *    builds the logout response url, sets the msg_url with the logout response url,
 *    sets the msg_body with NULL
 *
 * Optionaly ( if private key and certificates paths are set in server object )
 *    it signs the message (with X509 if a SOAP message,
 *    else with simple signature if a QUERY message )
 * 
 * Return value: 0 if ok, else < 0
 **/
gint
lasso_logout_build_response_msg(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoProvider *provider;
	gchar *url, *query;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

	profile = LASSO_PROFILE(logout);

	/* get the provider */
	provider = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
	if (provider == NULL) {
		return -1;
	}

	/* build logout response message */
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->msg_url = NULL;
		profile->msg_body = lasso_node_export_to_soap(profile->response,
				profile->server->private_key, profile->server->certificate);
		return 0;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		url = lasso_provider_get_metadata_one(provider, "SingleLogoutServiceReturnURL");
		if (url == NULL) {
			return -1;
		}
		query = lasso_node_export_to_query(profile->response,
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			return -1;
		}
		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		profile->msg_body = NULL;
		g_free(url);
		g_free(query);
		return 0;
	}

	return LASSO_PROFILE_ERROR_MISSING_REQUEST;
}

/**
 * lasso_logout_destroy:
 * @logout: the logout object
 *
 * destroy the logout object
 * 
 **/
void
lasso_logout_destroy(LassoLogout *logout)
{
	g_object_unref(G_OBJECT(logout));
}

/**
 * lasso_logout_get_next_providerID:
 * @logout: the logout object
 * 
 * This method returns the provider id from providerID_index in list of
 * providerIDs in session object.
 *
 * excepted the initial service provider id :
 *    It gets the remote provider id in session from the logout provider index
 *
 *    If it is the initial remote provider id, then it asks the next provider
 *    id from providerID_index + 1;
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
 * @logout: 
 * @remote_providerID: the providerID of the identity provider. When NULL, the first
 *                     identity provider is used.
 * @request_method: if set, then it get the protocol profile in metadata
 *                  corresponding of this HTTP request method.
 *
 * First it verifies session and identity are set.
 * Next, gets federation with the remote provider and gets the name identifier for the request.
 *       gets the protocol profile and build the logout request object.
 * If the local provider is a Service Provider and if the protocol profile is a HTTP Redirect / GET method,
 *       then removes the assertion.
 * 
 * Return value: 0 if ok, else < 0
 **/
gint
lasso_logout_init_request(LassoLogout *logout, char *remote_providerID, lassoHttpMethod http_method)
{
	LassoProfile      *profile;
	LassoProvider     *remote_provider;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoSamlAssertion *assertion;
	LassoFederation   *federation = NULL;
	gboolean           is_http_redirect_get_method = FALSE;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	/* verify if session exists */
	if (profile->session == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Session not found");
		return -1;
	}

	/* get the remote provider id
	   If remote_providerID is NULL, then get the first remote provider id in session */
	if (remote_providerID == NULL) {
		profile->remote_providerID = lasso_session_get_first_providerID(profile->session);
	} else {
		profile->remote_providerID = g_strdup(remote_providerID);
	}
	if (profile->remote_providerID == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "No remote provider id to build the logout request");
		return -1;
	}

	/* get assertion */
	assertion = lasso_session_get_assertion(profile->session, profile->remote_providerID);
	if (LASSO_IS_SAML_ASSERTION(assertion) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Assertion not found");
		return -1;
	}

	/* if format is one time, then get name identifier from assertion,
	   else get name identifier from federation */
	nameIdentifier = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(
			assertion->AuthenticationStatement)->Subject->NameIdentifier;
	if (strcmp(nameIdentifier->Format, LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME) != 0) {
		if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
			message(G_LOG_LEVEL_CRITICAL, "Identity not found");
			return -1;
		}
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (federation == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Federation not found");
			return -1;
		}

		nameIdentifier = lasso_profile_get_nameIdentifier(profile);
		if (nameIdentifier == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Name identifier not found for %s",
					profile->remote_providerID);
			return -1;
		}
	}

	/* get the provider */
	remote_provider = g_hash_table_lookup(
			profile->server->providers, profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Remote provider not found");
		return -1;
	}

	/* before setting profile->request, verify if it is already set */
	if (LASSO_IS_LIB_LOGOUT_REQUEST(profile->request) == TRUE) {
		lasso_node_destroy(profile->request);
		profile->request = NULL;
	}

	/* build a new request object from single logout protocol profile */

	/* get / verify http method */
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
			return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	/* build a new request object from http method */
	if (http_method == LASSO_HTTP_METHOD_SOAP) {
		profile->request = lasso_lib_logout_request_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_WITHX509,
				LASSO_SIGNATURE_METHOD_RSA_SHA1);
	}
	if (http_method == LASSO_HTTP_METHOD_REDIRECT) {
		is_http_redirect_get_method = TRUE;
		profile->request = lasso_lib_logout_request_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_NONE,
				0);
	}
	if (LASSO_IS_LIB_LOGOUT_REQUEST(profile->request) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Error while building the request");
		return -1;
	}

	/* Set the name identifier attribute with content local variable */
	profile->nameIdentifier = g_strdup(nameIdentifier->content);

	/* if logout request from a SP and if an HTTP Redirect / GET method, then remove assertion */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP && is_http_redirect_get_method) {
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);
	}

	/* Save the http method */
	logout->initial_http_request_method = http_method;

	return 0;
}

/**
 * lasso_logout_process_request_msg:
 * @logout: the logout object
 * @request_msg: the logout request message
 * 
 * Processes a logout request.
 *    if it is a SOAP request method then it builds the logout request object
 *    from the SOAP message and optionaly verifies the signature of the logout request.
 * 
 *    if it is a HTTP-Redirect request method then it builds the logout request object
 *    from the QUERY message and verify the signature.
 *
 *    Saves the HTTP request method.
 *    Saves the name identifier.
 *
 * Return value: 0 on success or a negative value otherwise.
 **/
gint lasso_logout_process_request_msg(LassoLogout *logout, char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
	g_return_val_if_fail(request_msg != NULL, -1);

	profile = LASSO_PROFILE(logout);

	profile->request = lasso_lib_logout_request_new();
	format = lasso_node_init_from_message(profile->request, request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			LASSO_LIB_LOGOUT_REQUEST(profile->request)->ProviderID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Unknown provider");
		return -1;
	}

	/* verify signatures */
	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "RequestID");

	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;

	profile->nameIdentifier = g_strdup(
			LASSO_LIB_LOGOUT_REQUEST(profile->request)->NameIdentifier->content);

	return profile->signature_status;
}


/**
 * lasso_logout_process_response_msg:
 * @logout: the logout object
 * @response_msg: the response message
 * 
 * Parses the response message and builds the response object.
 * Get the status code value :
 *     if it is not success, then if the local provider is a Service Provider and response method
 *     is SOAP, then builds a new logout request message for HTTP Redirect / GET method and returns
 *     the code error LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE and exits.
 *
 * Sets the remote provider id.
 * Sets the relay state.
 * 
 * if it is a SOAP method or, IDP provider type and http method is Redirect / GET,
 * then removes assertion.
 * 
 * If local server is an Identity Provider and if there is no more assertion
 * (Identity Provider has logged out every Service Providers),
 *     then restores the initial response.
 * Return value: 0 if OK else LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE or < 0
 **/
gint
lasso_logout_process_response_msg(LassoLogout *logout, gchar *response_msg)
{
	LassoProfile  *profile;
	LassoProvider *remote_provider;
	char *statusCodeValue;
	lassoHttpMethod response_method;
	LassoMessageFormat format;
	int rc;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	/* before verify if profile->response is set */
	if (LASSO_IS_LIB_LOGOUT_RESPONSE(profile->response) == TRUE) {
		lasso_node_destroy(profile->response);
		profile->response = NULL;
	}

	profile->response = lasso_lib_logout_response_new();
	format = lasso_node_init_from_message(profile->response, response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}
	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		response_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		response_method = LASSO_HTTP_METHOD_REDIRECT;

	/* get provider */
	profile->remote_providerID = LASSO_LIB_STATUS_RESPONSE(profile->response)->ProviderID;
	if (profile->remote_providerID == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "ProviderID not found");
		return LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID;
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid provider");
		return -1;
	}

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ResponseID");

	statusCodeValue = LASSO_LIB_STATUS_RESPONSE(profile->response)->Status->StatusCode->Value;

	if (strcmp(statusCodeValue, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		/* At SP, if the request method was a SOAP type, then rebuild the request
		 * message with HTTP method */
		if (strcmp(statusCodeValue, LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE) == 0 &&
				remote_provider->role == LASSO_PROVIDER_ROLE_IDP &&
				logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
			gchar *url, *query;

			/* Build and optionaly sign the logout request QUERY message */
			url = lasso_provider_get_metadata_one(remote_provider,
					"SingleLogoutServiceURL");
			query = lasso_node_export_to_query(profile->request,
					profile->server->signature_method,
					profile->server->private_key);
			profile->msg_url = g_strdup_printf("%s?%s", url, query);
			g_free(query);
			profile->msg_body = NULL;

			/* send a HTTP Redirect / GET method, so first remove session */
			lasso_session_remove_assertion(profile->session, profile->remote_providerID);

			return LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
		}
		message(G_LOG_LEVEL_CRITICAL, "Status code is not success : %s", statusCodeValue);
		return -1;
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
				lasso_node_destroy(profile->request);
			if (profile->response != NULL)
				lasso_node_destroy(profile->response);

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
 * @logout: the logout object
 * 
 * Reset the providerID_index attribute (set to 0).
 * 
 * Return value: 0
 **/
gint lasso_logout_reset_providerID_index(LassoLogout *logout)
{
  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  logout->providerID_index = 0;

  return 0;
}

/**
 * lasso_logout_validate_request:
 * @logout: the logout object
 * 
 * - Sets the remote provider id
 * - Sets a logout response with status code value to success.
 * - Verifies federation and authentication.
 * - If the request http method is a SOAP method, then verifies every other
 *   Service Providers supports SOAP method : if not, then sets status code
 *   value to UnsupportedProfile and returns a code error with
 *   LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE.
 * - Every tests are ok, then removes assertion.
 * - If local server is an Identity Provider and if there is more than one
 *   Service Provider (except the initial Service Provider), then saves the
 *   initial request, response and remote provider id.
 *
 * Return value: O if OK else < 0
 **/
gint
lasso_logout_validate_request(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoFederation *federation = NULL;
	LassoProvider *remote_provider;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoSamlAssertion *assertion;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	/* verify logout request */
	if (LASSO_IS_LIB_LOGOUT_REQUEST(profile->request) == FALSE)
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;

	profile->remote_providerID = g_strdup(
			LASSO_LIB_LOGOUT_REQUEST(profile->request)->ProviderID);

	/* get the provider */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL)
		return -1;

	/* Set LogoutResponse */
	profile->response = NULL;
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->response = lasso_lib_logout_response_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML_STATUS_CODE_SUCCESS,
				LASSO_LIB_LOGOUT_REQUEST(profile->request),
				LASSO_SIGNATURE_TYPE_WITHX509,
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
		message(G_LOG_LEVEL_CRITICAL, "Error while building response");
		return -1;
	}

	/* verify signature status */
	if (profile->signature_status != 0) {
		lasso_profile_set_response_status(profile, LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
	}

	/* Get the name identifier */
	nameIdentifier = LASSO_LIB_LOGOUT_REQUEST(profile->request)->NameIdentifier;
	if (nameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in logout request");
		lasso_profile_set_response_status(
				profile, LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_XML_ERROR_NODE_NOT_FOUND;
	}

	/* verify authentication */
	assertion = lasso_session_get_assertion(profile->session, profile->remote_providerID);
	if (assertion == NULL) {
		message(G_LOG_LEVEL_WARNING, "%s has no assertion", profile->remote_providerID);
		lasso_profile_set_response_status(profile, LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
		return -1;
	}

	/* If name identifier is federated, then verify federation */
	if (strcmp(nameIdentifier->Format, LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED) == 0) {
		if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
			message(G_LOG_LEVEL_CRITICAL, "Identity not found");
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return -1;
		}
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (LASSO_IS_FEDERATION(federation) == FALSE) {
			message(G_LOG_LEVEL_CRITICAL, "Federation not found");
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return -1;
		}

		if (lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
			message(G_LOG_LEVEL_WARNING, "No name identifier for %s",
					profile->remote_providerID);
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
			return -1;
		}
	}

	/* if SOAP request method at IDP then verify all the remote service providers support
	   SOAP protocol profile.
	   If one remote authenticated principal service provider doesn't support SOAP
	   then return UnsupportedProfile to original service provider */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {

		logout->private->all_soap = TRUE;
		g_hash_table_foreach(profile->server->providers,
				(GHFunc)check_soap_support, profile);

		if (logout->private->all_soap == FALSE) {
			lasso_profile_set_response_status(profile,
					LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE);
			return LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	/* FIXME : set the status code in response */

	/* authentication is ok, federation is ok, propagation support is ok, remove federation */
	lasso_session_remove_assertion(profile->session, profile->remote_providerID);

	/* if at IDP and nb sp logged > 1, then backup remote provider id,
	 * request and response
	 */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			g_hash_table_size(profile->session->assertions) >= 1) {
		logout->initial_remote_providerID = profile->remote_providerID;
		logout->initial_request = profile->request;
		logout->initial_response = profile->response;

		profile->remote_providerID = NULL;
		profile->request = NULL;
		profile->response = NULL;
	}

	return 0;
}



/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void check_soap_support(gchar *key, LassoProvider *provider, LassoProfile *profile)
{
	GList *supported_profiles;
	LassoSamlAssertion *assertion;

	if (strcmp(provider->ProviderID, profile->remote_providerID) == 0)
		return; /* original service provider (initiated logout) */

	assertion = lasso_session_get_assertion(profile->session, provider->ProviderID);
	if (assertion == NULL)
		return; /* not authenticated with this provider */

	supported_profiles = lasso_provider_get_metadata_list(provider,
			"SingleLogoutProtocolProfile");
	while (supported_profiles && strcmp(supported_profiles->data,
				LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP) != 0)
		supported_profiles = g_list_next(supported_profiles);

	if (supported_profiles)
		return; /* provider support profile */

	
	LASSO_LOGOUT(profile)->private->all_soap = FALSE;
}


static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode, *t;
	LassoLogout *logout = LASSO_LOGOUT(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "Logout");
	xmlSetProp(xmlnode, "LogoutDumpVersion", "2");

	if (logout->initial_request) {
		t = xmlNewTextChild(xmlnode, NULL, "InitialRequest", NULL);
		xmlAddChild(t, lasso_node_get_xmlNode(logout->initial_request));
	}

	if (logout->initial_response) {
		t = xmlNewTextChild(xmlnode, NULL, "InitialResponse", NULL);
		xmlAddChild(t, lasso_node_get_xmlNode(logout->initial_response));
	}

	if (logout->initial_remote_providerID)
		xmlNewTextChild(xmlnode, NULL, "InitialRemoteProviderID",
				logout->initial_remote_providerID);

	if (logout->providerID_index) {
		/* XXX: I don't think is is still necessary */
	}

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLogout *logout = LASSO_LOGOUT(node);
	xmlNode *t;

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "InitialRemoteProviderID") == 0)
			logout->initial_remote_providerID = xmlNodeGetContent(t);

		/* XXX: restore initial_request and initial_response */
		if (strcmp(t->name, "InitialRequest") == 0) {
			/* XXX */
		}
		if (strcmp(t->name, "InitialResponse") == 0) {
			/* XXX */
		}

		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoLogout *logout = LASSO_LOGOUT(object);
	if (logout->private->dispose_has_run) {
		return;
	}
	logout->private->dispose_has_run = TRUE;

	debug("Logout object 0x%x disposed ...", logout);

	/* unref reference counted objects */
	/* XXX
	lasso_node_destroy(logout->initial_request);
	lasso_node_destroy(logout->initial_response);
	*/

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{  
	LassoLogout *logout = LASSO_LOGOUT(object);
	debug("Logout object 0x%x finalized ...", logout);
	g_free(logout->initial_remote_providerID);
	g_free(logout->private);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLogout *logout)
{
	logout->private = g_new(LassoLogoutPrivate, 1);
	logout->private->dispose_has_run = FALSE;

	logout->initial_request = NULL;
	logout->initial_response = NULL;
	logout->initial_remote_providerID = NULL;

	logout->providerID_index = 0;
}

static void
class_init(LassoLogoutClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

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
 * @server: the logout object
 * @provider_type: the provider type (service provider or identity provider)
 * 
 * initialises a new logout object
 * 
 * Return value: a new instance of logout object or NULL
 **/
LassoLogout*
lasso_logout_new(LassoServer *server)
{
	LassoLogout *logout;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	logout = g_object_new(LASSO_TYPE_LOGOUT, NULL);
	LASSO_PROFILE(logout)->server = server;

	return logout;
}

LassoLogout*
lasso_logout_new_from_dump(LassoServer *server, const char *dump)
{
	LassoLogout *logout;
	xmlDoc *doc;

	logout = lasso_logout_new(server);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(logout), xmlDocGetRootElement(doc)); 

	return logout;
}

/**
 * lasso_logout_dump:
 * @logout: the logout object
 * 
 * This method dumps the logout object in string a xml message.
 * it first adds profile informations.
 * Next, it adds his logout informations (initial_request, initial_response,
 * initial_remote_providerID and providerID_index).
 * 
 * Return value: a newly allocated string or NULL
 **/
gchar *
lasso_logout_dump(LassoLogout *logout)
{
	return lasso_node_dump(LASSO_NODE(logout), NULL, 1);
}

