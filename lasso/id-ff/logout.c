/* $Id$ * * Lasso - A free implementation of the Liberty Alliance specifications.
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
 * SECTION:logout
 * @short_description: Single Logout Profile
 *
 * This profile Send logout notifications between providers. Any receiving provider must retransmit
 * the notification to any other providers with which it shares the current identity by any means
 * supported by the two, that is any provider federated with the current provider. There can be
 * partial failures if no binding can be found to notify a federating partner or if a partner fails
 * to respond.
 *
 * <para>It is generally advised to apply the local logout transaction before sending a logout request to
 * a partner. In short:
 * <itemizedlist>
 * <listitem><para>an identity provider receiving a logout request should kill the local
 * session before sending logout request to other service provider and proxyied identity
 * providers.</para></listitem>
 * <listitem><para>a service provider intitiating a logout request must first kill its local session,
 * then proceeds with the logout exchange with its identity provider</para></listitem>
 * </itemizedlist></para>
 *
 * <para>The following examples must not be used 'as-is' they lack most of the error checking code
 * that is needed for a secured and robust program, but they give an idea of how to use the
 * API</para>
 *
 * <example>
 * <title>Service Provider Initiated Logout</title>
 * <programlisting>
 * LassoLogout *logout;
 * char *session_dump; // must contain the session dump
 *                     // for the current user
 * int rc; // hold return codes
 * char *soap_response;
 *
 * LassoHttpMethod method; // method to use, LASSO_HTTP_METHOD_REDIRECT, 
 *                         // LASSO_HTTP_METHOD_POST or LASSO_HTTP_METHOD_SOAP,
 *                         // other methods are rarely supported
 *
 * logout = lasso_logout_new(server);
 * lasso_profile_set_session_from_dump(&logout-&gt;parent, session_dump);
 * // the second argument can be NULL, lasso_logout_init_request() will automatically choose the
 * // identity provider from the first assertion int the session
 * rc = lasso_logout_init_request(logout, "http://identity-provider-id/",
 *                 method);
 * if (rc != 0) {
 *   ... // handle errors, most of them are related to bad initialization
 *       // or unsupported binding
 * }
 * rc = lasso_logout_build_request_msg(logout);
 * if (rc != 0) {
 *   ... // handle errors, most of them are related to bad initialization
 *       // or impossibility to build the query string (missing private keys for signing)
 * }
 *
 * // now send the request
 * switch (method) {
 *     case LASSO_HTTP_METHOD_REDIRECT:
 *         // LASSO_PROFILE(logout)-&gt;msg_url contains the URL where the 
 *         // User Agent must be redirected
 *         ...
 *         // save the session and logout object, and store them attached to the RequestID of the
 *         // request, you will need them for handling the response
 *         session_dump = lasso_node_dump((LassoNode*)logout->parent.session);
 *         logout_dump = lasso_node_dump((LassoNode*)logout);
 *         break;
 *     case LASSO_HTTP_METHOD_POST:
 *         // you must build a form with a field name SAMLRequest (SAML 2.0) or LAREQ (ID-FF 1.2)
 *         // with the content of LASSO_PROFILE(logout)-&gt;msg_body
 *         // posting to the address LASSO_PROFILE(logout)-&gt;msg_url
 *         ...
 *         // save the session and logout object, and store them attached to the RequestID of the
 *         // request, you will need them for handling the response
 *         session_dump = lasso_node_dump((LassoNode*)logout->parent.session);
 *         logout_dump = lasso_node_dump((LassoNode*)logout);
 *         break;
 *     case LASSO_HTTP_SOAP:
 *         // makes a SOAP call, soap_call is NOT a Lasso function
 *         soap_response = soap_call(login-&gt;parent.msg_url, login-&gt;parent.msg_body);
 *         rc = lasso_logout_process_response_msg(logout, soap_response);
 *         if (rc != 0) {
 *             // handle errors, important ones are LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE meaning
 *             // that one other service provider of the current session cannot be contacted by the
 *             // identity provider with the current binding, for example it only accept REDIRECT
 *             (asynchronous-binding) or
 *             // POST an we are using SOAP (synchronous-binding).
 *             ...
 *         }
 *         // everything is ok save the session
 *         session_dump = lasso_node_dump(logout->parent.session);
 *         // nothing to save because you killed the local session already
 *         break;
 *     default:
 *         // other binding neither are frequent or largely supported
 *         // so report an error
 *         break;
 *     }
 * </programlisting>
 * </example>
 *
 * <para>The next example show the endpoint for handling response to request with asynchronous
 * binding (POST and Redirect).</para>
 *
 * <example>
 * <title>Service Provider Logout Request Endpoint</title>
 * <programlisting>
 * LassoLogout *logout;
 * char *request_method = getenv("REQUEST_METHOD");
 *
 * logout = lasso_logout_new(server);
 *
 * if (strcmp(request_method, "GET") == 0) {
 *     char query_string = getenv("QUERY_STRING");
 *     rc = lasso_logout_process_response_msg(logout, query_string);
 * } elif (strcmp(request_method, "POST") == 0) {
 *     char *message;
 *     // message should contain the content of LARES or SAMLResponse fied, depending if this is an
 *     // ID-FF 1.2 or SAML 2.0 service.
 *     rc = lasso_logout_process_response_msg(logout, message);
 * }
 * if (rc != 0) {
 *     // handle errors, as we are already unlogged, those must go to a log file or audit trail,
 *     // because at this time the user do not care anymore. A report about a failure to logout to
 *     // the IdP can be eventually shown.
 *     ...
 * }
 * </programlisting>
 * </example>
 *
 * <para>The next snippet show how to implement a logout endpoint, to receive a logout request and
 * respond.</para>
 *
 * <example>
 * <title>Service Provider Logout Request Endpoint</title>
 * <programlisting>
 * LassoLogout *logout;
 * char *session_dump;
 * char *request_method = getenv("REQUEST_METHOD");
 * int rc;
 * int method;
 *
 * logout = lasso_logout_new(server);
 * // server must be previously initialized, it can be kept around
 * // and used for many transaction, it is never modified by any profile
 * if (strcmp(request_method. "GET") == 0) {
 *     method = LASSO_HTTP_METHOD_REDIRECT;
 *     char query_string = getenv("QUERY_STRING");
 *     rc = lasso_logout_process_request_msg(logout, query_string);
 *     if (rc != 0) {
 *         // handle errors
 *         ...
 *     }
 * } else if (strcmp(request_method, "POST") == 0) {
 *     char *message;
 *     // read submitted content if this is a form, put LAREQ or SAMLRequest field into message and
	 *     set method to LASSO_HTTP_METHOD_POST
 *     // if content type is application/xml then put the full body of the POST inside message and
 *     // set method to LASSO_HTTP_METHOD_SOAP
 *     rc = lasso_logout_process_request_msg(logout, message);
 *     if (rc != 0) {
 *         // handle errors
 *         ...
 *     }
 * }
 * protocolProfile = lasso_provider_get_protocol_conformance(LASSO_PROVIDER(server));
 * if (protocolProfile == LASSO_LIBERTY_1_2) {
 *     char *session_index;
 *     LassoSamlNameIdentifier *name_id;
 *     LibLogoutRequest *logout_request;
 *
 *     logout_request = LIB_LOGOUT_REQUEST(LASSO_PROFILE(logout)-&gt;request);
 *     session_index = logout_request-&gt;SessionIndex;
 *     name_id = logout_request-&gt;NameIdentifier;
 *     // lookup the session dump using session_index and name_id
 * } else if (protocolProfile == LASSO_SAML_2_0) {
 *     char *session_index;
 *     LassoSaml2NameID *name_id;
 *     LassoSamlp2LogoutRequest *logout_request;
 *
 *     logout_request = LASSO_SAMLP2_LOGOUT_REQUEST(LASSO_PROFILE(logout)-&gt;request);
 *     session_index = logout_request-&gt;SessionIndex;
 *     name_id = logout_request-&gt;NameID;
 *     // lookup the session dump using session_index and name_id
 * }
 * lasso_profile_set_session_from_dump(LASSO_PROFILE(logout), session_dump);
 * // you can check other property of the request here if you want
 * // 
 * if (request is accepted) {
 *     rc = lasso_logout_validate_request(logout);
 *     if (rc != 0) {
 *         // handle errors..
 *         ...
 *     } else {
 *     .... // kill the local session
 *          // if local server is an identity provider, then traverse the session using
 *          // lasso_logout_get_next_providerID() and send logout request to all logged 
 *          // service providers.
 *     }
 * }
 * // if lasso_logout_validate_request() was not called this will automatically create a Failure
 * // response.
 * rc = lasso_logout_build_response_msg(logout);
 * if (rc != 0) {
 *     // handle errors..
 *     ...
 * }
 * // the response is produced with the same binding as the request
 * // see the previous request example for how to send the response
 * // the only change is for SOAP, you just need to print the msg_body as page content with a
 * // Content-type of application/xml.
 * </programlisting>
 * </example>
 */

#include "../xml/private.h"
#include "../xml/lib_authentication_statement.h"

#include "logout.h"
#include "logoutprivate.h"

#include "profileprivate.h"
#include "providerprivate.h"
#include "sessionprivate.h"

#include "../saml-2.0/logoutprivate.h"
#include "../utils.h"

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
lasso_error_t
lasso_logout_build_request_msg(LassoLogout *logout)
{
	LassoProfile *profile = NULL;
	LassoProvider *remote_provider = NULL;
	char *url = NULL;
	char *query = NULL;
	lasso_error_t rc = 0;

	lasso_bad_param(LOGOUT, logout);

	profile = LASSO_PROFILE(logout);
	lasso_profile_clean_msg_info(profile);

	IF_SAML2(profile) {
		return lasso_saml20_logout_build_request_msg(logout);
	}

	if (profile->remote_providerID == NULL) {
		/* it means lasso_logout_init_request was not called before */
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	/* get remote provider */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		goto_cleanup_with_rc(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* build the logout request message */
	if (logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
		/* build the logout request message */
		lasso_assign_new_string(profile->msg_url, lasso_provider_get_metadata_one(
				remote_provider, "SoapEndpoint"));
		/* FIXME: private key file is not owned by the request ? That is potentially a
		 * problem if the server life does not exceed the request */
		lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(logout->parent.server,
					profile->remote_providerID, profile->request));
		lasso_assign_new_string(profile->msg_body,
				lasso_node_export_to_soap(profile->request));
	} else if (logout->initial_http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* build and optionally sign the logout request QUERY message */
		url = lasso_provider_get_metadata_one(remote_provider,
				"SingleLogoutServiceURL");
		if (url == NULL)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		lasso_check_good_rc(lasso_server_export_to_query_for_provider_by_name(profile->server,
					profile->remote_providerID, profile->request, &query));
		if (query == NULL)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		/* build the msg_url */
		lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
		lasso_release_string(profile->msg_body);
	} else {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}
cleanup:
	lasso_release(url);
	lasso_release(query);
	return rc;
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
lasso_error_t
lasso_logout_build_response_msg(LassoLogout *logout)
{
	LassoProfile *profile = NULL;
	LassoProvider *provider = NULL;
	gchar *url = NULL;
	gchar *query = NULL;
	lasso_error_t rc = 0;

	lasso_bad_param(LOGOUT, logout);
	profile = &logout->parent;
	lasso_profile_clean_msg_info(profile);

	if (! profile->private_data || ! logout->private_data) {
		return LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT;
	}

	IF_SAML2(profile) {
		return lasso_saml20_logout_build_response_msg(logout);
	}

	if (profile->response == NULL) {
		if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
			lasso_assign_new_gobject(profile->response,
					lasso_lib_logout_response_new_full(
						LASSO_PROVIDER(profile->server)->ProviderID,
						LASSO_SAML_STATUS_CODE_REQUEST_DENIED,
						LASSO_LIB_LOGOUT_REQUEST(profile->request),
						profile->server->certificate ?
						LASSO_SIGNATURE_TYPE_WITHX509 :
						LASSO_SIGNATURE_TYPE_SIMPLE,
						LASSO_SIGNATURE_METHOD_RSA_SHA1));
		} else if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
			lasso_assign_new_gobject(profile->response,
					lasso_lib_logout_response_new_full(
						LASSO_PROVIDER(profile->server)->ProviderID,
						LASSO_SAML_STATUS_CODE_REQUEST_DENIED,
						LASSO_LIB_LOGOUT_REQUEST(profile->request),
						LASSO_SIGNATURE_TYPE_NONE,
						0));
		}
	}

	if (profile->remote_providerID == NULL || profile->response == NULL) {
		/* no remote provider id set or no response set, this means
		 * this function got called before validate_request, probably
		 * because there were no active session */
		goto_cleanup_with_rc(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* Set the RelayState */
	lasso_assign_string(LASSO_LIB_STATUS_RESPONSE(profile->response)->RelayState,
			profile->msg_relayState);

	/* build logout response message */
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		lasso_release_string(profile->msg_url);
		lasso_check_good_rc(lasso_server_set_signature_for_provider_by_name(logout->parent.server,
					profile->remote_providerID, profile->response));
		lasso_assign_new_string(profile->msg_body,
				lasso_node_export_to_soap(profile->response));
	} else if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		lasso_release_string(profile->msg_body);
		provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (provider == NULL)
			goto_cleanup_with_rc(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

		url = lasso_provider_get_metadata_one(provider, "SingleLogoutServiceReturnURL");
		if (url == NULL)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		lasso_check_good_rc(lasso_server_export_to_query_for_provider_by_name(profile->server,
					profile->remote_providerID, profile->response, &query));
		if (query == NULL)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
	} else {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

cleanup:
	lasso_release_string(url);
	lasso_release_string(query);
	return rc;
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
	lasso_node_destroy(LASSO_NODE(logout));
}

/**
 * lasso_logout_get_next_providerID:
 * @logout: a #LassoLogout
 *
 * Returns the provider id from providerID_index in list of providerIDs in
 * principal session with the exception of initial service provider ID.
 *
 * Return value:(transfer full): a newly allocated string or NULL
 **/
gchar*
lasso_logout_get_next_providerID(LassoLogout *logout)
{
	LassoProfile *profile;
	gchar        *providerID;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);
	profile = LASSO_PROFILE(logout);

	if (profile->session == NULL) {
		return NULL;
	}

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
	LassoSamlNameIdentifier *nameIdentifier = NULL;
	gboolean           is_http_redirect_get_method = FALSE;
	LassoSession *session;
	GList *name_ids = NULL;
	GList *session_indexes = NULL;
	LassoLibLogoutRequest *lib_logout_request = NULL;
	LassoSamlpRequestAbstract *request_abstract = NULL;
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	/* verify if session exists */
	session = lasso_profile_get_session(profile);
	if (session == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	}

	/* get the remote provider id
	   If remote_providerID is NULL, then get the first remote provider id in session */
	lasso_release(profile->remote_providerID);
	if (remote_providerID == NULL) {
		lasso_assign_new_string(profile->remote_providerID, lasso_session_get_provider_index(session, 0));
	} else {
		lasso_assign_string(profile->remote_providerID, remote_providerID);
	}
	if (profile->remote_providerID == NULL) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	/* get the provider */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		goto_cleanup_with_rc(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	IF_SAML2(profile) {
		return lasso_saml20_logout_init_request(logout, remote_provider, http_method);
	}

	name_ids = lasso_session_get_name_ids(session, profile->remote_providerID);
	if (! name_ids) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER);
	}
	nameIdentifier = name_ids->data;
	lasso_assign_gobject(profile->nameIdentifier, nameIdentifier);
	session_indexes = lasso_session_get_session_indexes(session,
			profile->remote_providerID, profile->nameIdentifier);

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
				lasso_session_remove_assertion(session,
						profile->remote_providerID);
				if (logout->initial_remote_providerID && logout->initial_request) {
					lasso_assign_string(profile->remote_providerID,
							logout->initial_remote_providerID);
					lasso_assign_new_gobject(profile->response, lasso_lib_logout_response_new_full(
							LASSO_PROVIDER(profile->server)->ProviderID,
							LASSO_SAML_STATUS_CODE_SUCCESS,
							LASSO_LIB_LOGOUT_REQUEST(logout->initial_request),
							LASSO_SIGNATURE_TYPE_NONE,
							0));
				}
			}
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
		}
	}

	/* build a new request object from http method */
	if (http_method == LASSO_HTTP_METHOD_SOAP) {
		lib_logout_request = (LassoLibLogoutRequest*)lasso_lib_logout_request_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				profile->server->certificate ?
				LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
				LASSO_SIGNATURE_METHOD_RSA_SHA1);
	} else { /* http_method == LASSO_HTTP_METHOD_REDIRECT */
		is_http_redirect_get_method = TRUE;
		lib_logout_request = (LassoLibLogoutRequest*)lasso_lib_logout_request_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_NONE,
				0);
	}
	request_abstract = &lib_logout_request->parent;

	if (lasso_provider_get_protocol_conformance(remote_provider) < LASSO_PROTOCOL_LIBERTY_1_2) {
		request_abstract->MajorVersion = 1;
		request_abstract->MinorVersion = 1;
	}

	lasso_lib_logout_request_set_session_indexes(lib_logout_request, session_indexes);
	lasso_assign_string(lib_logout_request->RelayState, profile->msg_relayState);

	/* if logout request from a SP and if an HTTP Redirect/GET method, then remove assertion */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP && is_http_redirect_get_method) {
		lasso_session_remove_assertion(session, profile->remote_providerID);
	}

	/* Save the http method */
	logout->initial_http_request_method = http_method;
	lasso_assign_gobject(profile->request, lib_logout_request);
cleanup:
	lasso_release_gobject(lib_logout_request);
	lasso_release_list_of_strings(session_indexes);
	lasso_release_list_of_gobjects(name_ids);
	return rc;
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
	LassoLibLogoutRequest *logout_request;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(logout);

	IF_SAML2(profile) {
		return lasso_saml20_logout_process_request_msg(logout, request_msg);
	}

	lasso_assign_new_gobject(profile->request, lasso_lib_logout_request_new());
	format = lasso_node_init_from_message(LASSO_NODE(profile->request), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR || ! LASSO_IS_LIB_LOGOUT_REQUEST(profile->request)) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	logout_request = LASSO_LIB_LOGOUT_REQUEST(profile->request);

	/* Validate some schema constraints */
	if (logout_request->ProviderID == NULL
			|| LASSO_IS_SAML_NAME_IDENTIFIER(logout_request->NameIdentifier) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	lasso_assign_string(profile->msg_relayState,
			logout_request->RelayState);
	lasso_assign_string(profile->remote_providerID,
			logout_request->ProviderID);

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* verify signatures */
	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "RequestID", format);

	switch (format) {
		case LASSO_MESSAGE_FORMAT_SOAP:
			profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
			break;
		case LASSO_MESSAGE_FORMAT_QUERY:
			profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;
			break;
		default:
			return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	lasso_assign_gobject(profile->nameIdentifier,
			LASSO_NODE(logout_request->NameIdentifier));

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
lasso_error_t
lasso_logout_process_response_msg(LassoLogout *logout, gchar *response_msg)
{
	LassoProfile  *profile = NULL;
	LassoProvider *remote_provider = NULL;
	char *statusCodeValue = NULL;
	LassoHttpMethod response_method;
	LassoMessageFormat format;
	LassoLibStatusResponse *response = NULL;
	lasso_error_t rc = 0;
	gchar *url = NULL;
	gchar *query = NULL;


	lasso_bad_param(LOGOUT, logout);
	lasso_null_param(response_msg);
	profile = &logout->parent;

	IF_SAML2(profile) {
		return lasso_saml20_logout_process_response_msg(logout, response_msg);
	}

	lasso_assign_new_gobject(profile->response, lasso_lib_logout_response_new());
	format = lasso_node_init_from_message(LASSO_NODE(profile->response), response_msg);

	switch (format) {
		case LASSO_MESSAGE_FORMAT_SOAP:
			response_method = LASSO_HTTP_METHOD_SOAP;
			break;
		case LASSO_MESSAGE_FORMAT_QUERY:
			response_method = LASSO_HTTP_METHOD_REDIRECT;
			break;
		default:
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	/* get the RelayState */
	lasso_assign_string(profile->msg_relayState,
			LASSO_LIB_STATUS_RESPONSE(profile->response)->RelayState);
	/* get provider */
	lasso_assign_string(profile->remote_providerID,
			LASSO_LIB_STATUS_RESPONSE(profile->response)->ProviderID);
	if (profile->remote_providerID == NULL)
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE)
		goto_cleanup_with_rc(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ResponseID", format);
	if (rc == LASSO_DS_ERROR_SIGNATURE_NOT_FOUND) {
		/* This message SHOULD be signed.
		 *  -- draft-liberty-idff-protocols-schema-1.2-errata-v2.0.pdf - p38
		 */
		debug("No signature on logout response");
		rc = 0;
	} else {
		goto cleanup;
	}

	response = LASSO_LIB_STATUS_RESPONSE(profile->response);

	if (response->Status == NULL || response->Status->StatusCode == NULL
			|| response->Status->StatusCode->Value == NULL) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	}
	statusCodeValue = response->Status->StatusCode->Value;

	if (strcmp(statusCodeValue, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		/* At SP, if the request method was a SOAP type, then rebuild the request
		 * message with HTTP method */

		/* takes lower-level StatusCode if available */
		if (response->Status->StatusCode && response->Status->StatusCode->StatusCode)
			statusCodeValue = response->Status->StatusCode->StatusCode->Value;

		if (lasso_strisequal(statusCodeValue, LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE) &&
				remote_provider->role == LASSO_PROVIDER_ROLE_IDP &&
				logout->initial_http_request_method == LASSO_HTTP_METHOD_SOAP) {
			/* Build and optionally sign the logout request QUERY message */
			lasso_release(profile->msg_body);
			url = lasso_provider_get_metadata_one(remote_provider,
					"SingleLogoutServiceURL");
			if (url == NULL)
				goto_cleanup_with_rc(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);

			lasso_check_good_rc(lasso_server_export_to_query_for_provider_by_name(profile->server,
						profile->remote_providerID, profile->request,
						&query));
			if (query == NULL)
				goto_cleanup_with_rc(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
			lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));

			/* send a HTTP Redirect / GET method, so first remove session */
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);

			goto_cleanup_with_rc(LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE);
		} else if (lasso_strisequal(statusCodeValue, LASSO_SAML_STATUS_CODE_REQUEST_DENIED)) {
			/* assertion no longer on idp so removing it locally too */
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);
			goto_cleanup_with_rc(LASSO_LOGOUT_ERROR_REQUEST_DENIED);
		} else if (lasso_strisequal(statusCodeValue,
					LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST)) {
			/* how could this happen ?  probably error in SP */
			/* let's remove the assertion nevertheless */
			lasso_session_remove_assertion(
					profile->session, profile->remote_providerID);
			goto_cleanup_with_rc(LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND);
		}
		error("Status code is not success : %s", statusCodeValue);
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS);
	}


	/* if SOAP method or, if IDP provider type and HTTP Redirect, then remove assertion */
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
			lasso_session_count_assertions(profile->session) <= 0) {
		remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
		if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
			lasso_transfer_string(profile->remote_providerID,
					logout->initial_remote_providerID);
			lasso_transfer_gobject(profile->request, logout->initial_request);
			lasso_transfer_gobject(profile->response, logout->initial_response);
		}
	}
cleanup:
	lasso_release_string(url);
	lasso_release_string(query);
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
 * <listitem><para>
 *   Sets the remote provider id
 * </para></listitem>
 * <listitem><para>
 *   Sets a logout response with status code value to success.
 * </para></listitem>
 * <listitem><para>
 *   Checks current signature status, if verification failed, stop processing
 *   and set the status code value to failure.
 * </para></listitem>
 * <listitem><para>
 *   Verifies federation and authentication.
 * </para></listitem>
 * <listitem><para>
 *   If the request http method is a SOAP method, then verifies every other
 *   Service Providers supports SOAP method : if not, then sets status code
 *   value to UnsupportedProfile and returns a code error with
 *   LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE.
 * </para></listitem>
 * <listitem><para>
 *   Every tests are ok, then removes assertion.
 * </para></listitem>
 * <listitem><para>
 *   If local server is an Identity Provider and if there is more than one
 *   Service Provider (except the initial Service Provider), then saves the
 *   initial request, response and remote provider id.
 * </para></listitem>
 * </itemizedlist>
 *
 * Return value: 0 on success; or
 * LASSO_PROFILE_ERROR_MISSING_REQUEST if no request has been found -- usually means that
 * lasso_logout_process_request_msg was not called,
 * LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the requesting provider is not known to the server object,
 * LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED if creation of the response object failed,
 * LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND if the request do not contain a NameID element,
 * LASSO_PROFILE_ERROR_SESSION_NOT_FOUND if the logout profile object do not contain a session
 * object,
 * LASSO_PROFILE_ERROR_MISSING_ASSERTION if no assertion from the requesting provider was found,
 * LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND if the logout profile object do not contain an identity
 * object,
 * LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND if no federation for the requesting provider was found,
 * LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE if the requested HTTP method is not supported by all the
 * remote provider of the current session.
 *
 **/
gint
lasso_logout_validate_request(LassoLogout *logout)
{
	LassoProfile *profile;
	LassoFederation *federation = NULL;
	LassoProvider *remote_provider;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoNode *assertion_n;
	LassoLibLogoutRequest *logout_request = NULL;

	g_return_val_if_fail(LASSO_IS_LOGOUT(logout), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(logout);

	IF_SAML2(profile) {
		return lasso_saml20_logout_validate_request(logout);
	}

	/* verify logout request */
	if (LASSO_IS_LIB_LOGOUT_REQUEST(profile->request) == FALSE) {
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}
	logout_request = LASSO_LIB_LOGOUT_REQUEST(profile->request);

	lasso_assign_string(profile->remote_providerID,
			logout_request->ProviderID);

	/* get the provider */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* Set LogoutResponse */
	lasso_release_gobject(profile->response);
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		lasso_assign_new_gobject(profile->response, lasso_lib_logout_response_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML_STATUS_CODE_SUCCESS,
				logout_request,
				profile->server->certificate ?
					LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
				LASSO_SIGNATURE_METHOD_RSA_SHA1));
	}
	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		lasso_assign_new_gobject(profile->response, lasso_lib_logout_response_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				LASSO_SAML_STATUS_CODE_SUCCESS,
				logout_request,
				LASSO_SIGNATURE_TYPE_NONE,
				0));
	}
	if (LASSO_IS_LIB_LOGOUT_RESPONSE(profile->response) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED);
	}

	/* copy the RelayState */
	lasso_assign_string(LASSO_LIB_STATUS_RESPONSE(profile->response)->RelayState,
			profile->msg_relayState);

	/* Verify signature status, if signature is invalid, stop validation here */
	if (profile->signature_status != 0) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
		return profile->signature_status;
	}

	/* Get the name identifier */
	nameIdentifier = logout_request->NameIdentifier;
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

	/* if at IDP and nb sp logged >= 1, then backup remote provider id,
	 * request and response
	 */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP &&
			lasso_session_count_assertions(profile->session) >= 1) {
		lasso_transfer_string(logout->initial_remote_providerID, profile->remote_providerID);
		lasso_transfer_gobject(logout->initial_request, profile->request);
		lasso_transfer_gobject(logout->initial_response, profile->response);
	}

	return 0;
}



/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "InitialRequest", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoLogout, initial_request), NULL, NULL, NULL},
	{ "InitialResponse", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoLogout, initial_response), NULL, NULL, NULL},
	{ "InitialRemoteProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLogout, initial_remote_providerID), NULL, NULL, NULL},
	{ "InitialHttpRequestMethod", SNIPPET_CONTENT | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoLogout, initial_http_request_method), NULL, NULL, NULL},
	{ "LogoutDumpVersion", SNIPPET_ATTRIBUTE, 0, NULL, NULL, NULL },
	/* "ProviderIdIndex" must not be dumped (since apps assume to get
	 * it back to 0 after a restore from dump) (maybe this behaviour should
	 * be fixed)
	 */
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
check_soap_support(G_GNUC_UNUSED gchar *key, LassoProvider *provider, LassoProfile *profile)
{
	const GList *supported_profiles;
	LassoNode *assertion_n;

	if (strcmp(provider->ProviderID, profile->remote_providerID) == 0)
		return; /* original service provider (initiated logout) */

	assertion_n = lasso_session_get_assertion(profile->session, provider->ProviderID);
	if (LASSO_IS_SAML_ASSERTION(assertion_n) == FALSE) {
		return; /* not authenticated with this provider */
	}

	supported_profiles = lasso_provider_get_metadata_list(provider,
			"SingleLogoutProtocolProfile");
	while (supported_profiles && strcmp(supported_profiles->data,
				LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP) != 0)
		supported_profiles = g_list_next(supported_profiles);

	if (supported_profiles)
		return; /* provider support profile */


	LASSO_LOGOUT(profile)->private_data->all_soap = FALSE;
	LASSO_LOGOUT(profile)->private_data->partial_logout = FALSE;
}


static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoLogout *logout;

	if (! LASSO_IS_LOGOUT(node)) {
		return NULL;
	}
	logout = (LassoLogout*)node;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)"Logout");
	xmlSetProp(xmlnode, (xmlChar*)"LogoutDumpVersion", (xmlChar*)"2");
	if (logout->private_data->partial_logout) {
		xmlSetProp(xmlnode, (xmlChar*)"PartialLogout", (xmlChar*)"true");
	}

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc = 0;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc == 0) {
		xmlChar *tmp;
		tmp = xmlGetProp(xmlnode, (xmlChar*)"PartiaLogout");
		if (tmp && strcmp((char*)tmp, "true") == 0) {
			((LassoLogout*)node)->private_data->partial_logout = TRUE;
		}
		lasso_release_xml_string(tmp);
	}
	return rc;
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
	lasso_release(logout->private_data);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLogout *logout)
{
	logout->initial_http_request_method = LASSO_HTTP_METHOD_NONE;
	logout->private_data = g_new0(LassoLogoutPrivate, 1);
	logout->private_data->dispose_has_run = FALSE;
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
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
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
			NULL
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
	lasso_assign_gobject(LASSO_PROFILE(logout)->server, server);

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

	logout = (LassoLogout*)lasso_node_new_from_dump(dump);
	if (! LASSO_IS_LOGOUT(logout)) {
		lasso_release_gobject(logout);
	} else {
		lasso_assign_gobject(logout->parent.server, server);
	}
	return logout;
}

/**
 * lasso_logout_dump:
 * @logout: a #LassoLogout
 *
 * Dumps @logout content to an XML string.
 *
 * Return value:(transfer full): the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_logout_dump(LassoLogout *logout)
{
	return lasso_node_dump(LASSO_NODE(logout));
}
