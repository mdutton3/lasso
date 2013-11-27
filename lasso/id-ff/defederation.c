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
 * SECTION:defederation
 * @short_description: Federation Termination Notification Profile (ID-FF)
 *
 * The Federation Termination Notification Profiles serves to suppress federations between identity
 * providers and services providers. It can be initiated by any of the partners using Redirect
 * or SOAP binding.
 *
 **/

#include "../xml/private.h"
#include "defederation.h"

#include "providerprivate.h"
#include "sessionprivate.h"
#include "identityprivate.h"
#include "profileprivate.h"
#include "serverprivate.h"
#include "../xml/private.h"
#include "../utils.h"

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_defederation_build_notification_msg:
 * @defederation: a #LassoDefederation
 *
 * Builds the federation termination notification message.
 *
 * It gets the federation termination notification protocol profile and:
 * <itemizedlist>
 * <listitem><para>
 *   if it is a SOAP method, then it builds the federation termination
 *   notification SOAP message, optionally signs the notification node, sets
 *   @msg_body, gets the SoapEndpoint url and sets @msg_url of the federation
 *   termination object.
 * </para></listitem>
 * <listitem><para>
 *   if it is a HTTP-Redirect method, then it builds the federation termination
 *   notification QUERY message (optionally signs the notification message),
 *   builds the federation termination notification url with federation
 *   termination service url, sets @msg_url in the federation termination
 *   object, sets @msg_body to NULL.
 * </para></listitem>
 * </itemizedlist>
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_defederation_build_notification_msg(LassoDefederation *defederation)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	gchar *url, *query;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(defederation);
	lasso_profile_clean_msg_info(profile);

	if (profile->remote_providerID == NULL) {
		/* this means lasso_defederation_init_notification was not called before */
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	/* get the remote provider object */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* build the federation termination notification message (SOAP or HTTP-Redirect) */
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		/* build the logout request message */
		lasso_assign_new_string(profile->msg_url, lasso_provider_get_metadata_one(
				remote_provider, "SoapEndpoint"));
		lasso_assign_string(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->private_key_file,
			profile->server->private_key);
		lasso_assign_string(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->certificate_file,
			profile->server->certificate);
		lasso_assign_new_string(profile->msg_body, lasso_node_export_to_soap(LASSO_NODE(profile->request)));
		return 0;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* build and optionally sign the query message and build the
		 * federation termination notification url */
		url = lasso_provider_get_metadata_one(remote_provider,
				"FederationTerminationServiceURL");
		if (url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}
		query = lasso_node_export_to_query_with_password(LASSO_NODE(profile->request),
				profile->server->signature_method,
				profile->server->private_key,
				profile->server->private_key_password);

		if (query == NULL) {
			lasso_release(url);
			return critical_error(LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
		}

		lasso_assign_new_string(profile->msg_url, lasso_concat_url_query(url, query));
		lasso_release(profile->msg_body);
		lasso_release(url);
		lasso_release(query);

		return 0;
	}

	return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
}

/**
 * lasso_defederation_destroy:
 * @defederation: a #LassoDefederation
 *
 * Destroys a #LassoDefederation object.
 **/
void
lasso_defederation_destroy(LassoDefederation *defederation)
{
	lasso_node_destroy(LASSO_NODE(defederation));
}

/**
 * lasso_defederation_init_notification:
 * @defederation: a #LassoDefederation
 * @remote_providerID: the provider id of the federation termination notified
 *     provider.
 * @http_method: the HTTP method to send the message.
 *
 * Sets a new federation termination notification to the remote provider id
 * with the provider id of the requester (from the server object) and the name
 * identifier of the federated principal.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_defederation_init_notification(LassoDefederation *defederation, gchar *remote_providerID,
		LassoHttpMethod http_method)
{
	LassoProfile*profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlNameIdentifier *nameIdentifier;
	LassoNode *nameIdentifier_n;
	gint rc = 0;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(defederation);

	lasso_release(profile->remote_providerID);
	lasso_release_gobject(profile->request);

	if (remote_providerID != NULL) {
		lasso_assign_string(profile->remote_providerID, remote_providerID);
	} else {
		LassoProvider *my_provider;
		LassoProviderRole role = LASSO_PROVIDER_ROLE_IDP;

		lasso_extract_node_or_fail(my_provider, profile->server, PROVIDER,
				LASSO_PROFILE_ERROR_MISSING_SERVER);
		if (my_provider->role == LASSO_PROVIDER_ROLE_IDP) {
			role = LASSO_PROVIDER_ROLE_SP;
		}
		lasso_assign_new_string(profile->remote_providerID,
				lasso_server_get_first_providerID_by_role(profile->server, role));
	}
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* get federation */
	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (federation == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}

	/* get the nameIdentifier to send the federation termination notification */
	nameIdentifier_n = lasso_profile_get_nameIdentifier(profile);
	if (nameIdentifier_n == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND);
	}
	nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(nameIdentifier_n);

	if (federation->local_nameIdentifier) {
		lasso_assign_gobject(profile->nameIdentifier, federation->local_nameIdentifier);
	} else {
		lasso_assign_gobject(profile->nameIdentifier, LASSO_NODE(nameIdentifier));
	}

	/* get / verify http method */
	if (http_method == LASSO_HTTP_METHOD_ANY) {
		http_method = lasso_provider_get_first_http_method(
				LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_FEDERATION_TERMINATION);
	} else {
		if (lasso_provider_accept_http_method(LASSO_PROVIDER(profile->server),
					remote_provider,
					LASSO_MD_PROTOCOL_TYPE_FEDERATION_TERMINATION,
					http_method,
					TRUE) == FALSE) {
			return critical_error(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
		}
	}

	/* build the request */
	if (http_method == LASSO_HTTP_METHOD_SOAP) {
		profile->request = lasso_lib_federation_termination_notification_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				profile->server->certificate ?
					LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
				LASSO_SIGNATURE_METHOD_RSA_SHA1);
		if (profile->msg_relayState) {
			message(G_LOG_LEVEL_WARNING,
					"RelayState was defined but can't be used "\
					"in SOAP Federation Termination Notification", NULL);
		}

	} else { /* LASSO_HTTP_METHOD_REDIRECT */
		profile->request = lasso_lib_federation_termination_notification_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_NONE,
				0);
		lasso_assign_string(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(profile->request)->RelayState,
			profile->msg_relayState);
	}

	if (lasso_provider_get_protocol_conformance(remote_provider) < LASSO_PROTOCOL_LIBERTY_1_2) {
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MajorVersion = 1;
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MinorVersion = 1;
	}

	/* remove federation with remote provider id */
	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}
	lasso_identity_remove_federation(profile->identity, profile->remote_providerID);

	/* remove assertion from session */
	if (profile->session)
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);

	/* Save notification method */
	profile->http_request_method = http_method;

cleanup:
	return rc;
}

/**
 * lasso_defederation_process_notification_msg:
 * @defederation: the federation termination object
 * @notification_msg: the federation termination notification message
 *
 * Processes a lib:FederationTerminationNotification message.  Rebuilds a
 * request object from the message and optionally verifies its signature.
 *
 * Set the msg_nameIdentifier attribute with the NameIdentifier content of the
 * notification object and optionally set the msg_relayState attribute with the
 * RelayState content of the notification object.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_defederation_process_notification_msg(LassoDefederation *defederation, char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(defederation);

	lasso_assign_new_gobject(profile->request, lasso_lib_federation_termination_notification_new());
	format = lasso_node_init_from_message(LASSO_NODE(profile->request), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		lasso_assign_new_string(profile->msg_relayState,
				lasso_get_relaystate_from_query(request_msg));
	}

	lasso_assign_string(profile->remote_providerID, LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
				profile->request)->ProviderID);
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "RequestID", format);

	/* set the http request method */
	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;

	lasso_assign_gobject(profile->nameIdentifier, LASSO_NODE(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
				profile->request)->NameIdentifier));

	/* get the RelayState (only available in redirect mode) */
	if (LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(profile->request)->RelayState)
		lasso_assign_string(profile->msg_relayState,
				LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
					profile->request)->RelayState);

	return profile->signature_status;
}

/**
 * lasso_defederation_validate_notification:
 * @defederation: a #LassoDefederation
 *
 * Checks notification with regards to message status and principal
 * federations; update them accordingly.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_defederation_validate_notification(LassoDefederation *defederation)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation = NULL;
	LassoSamlNameIdentifier *nameIdentifier;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(defederation);

	/* verify the federation termination notification */
	if (LASSO_IS_LIB_FEDERATION_TERMINATION_NOTIFICATION(profile->request) == FALSE)
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;

	/* If SOAP notification, then msg_url and msg_body are NULL */
	/* if HTTP-Redirect notification, set msg_url with the federation
	 * termination service return url, and set msg_body to NULL */
	lasso_release(profile->msg_url)
	lasso_release(profile->msg_body)

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		remote_provider = lasso_server_get_provider(profile->server,
				profile->remote_providerID);
		if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
			return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
		}

		/* build the QUERY and the url. Dont need to sign the query,
		 * only the relay state is optinaly added and it is crypted
		 * by the notifier */
		profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
				"FederationTerminationServiceReturnURL");
		if (profile->msg_url == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
		}

		/* if a relay state, then build the query part */
		if (profile->msg_relayState) {
			gchar *url;
			gchar *query = g_strdup_printf("RelayState=%s", profile->msg_relayState);
			url = lasso_concat_url_query(profile->msg_url, query);
			lasso_release(query);
			lasso_assign_new_string(profile->msg_url, url);
		}
	}

	/* get the name identifier */
	nameIdentifier = LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
			profile->request)->NameIdentifier;
	if (nameIdentifier == NULL) {
		return critical_error(LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER);
	}

	/* Verify federation */
	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (federation == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}

	if (lasso_federation_verify_name_identifier(federation,
				LASSO_NODE(nameIdentifier)) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND);
	}

	/* remove federation of the remote provider */
	lasso_identity_remove_federation(profile->identity, profile->remote_providerID);

	/* if defederation has a session and if there is an assertion for remote provider id,
	   then remove assertion too  */
	if (profile->session != NULL) {
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);
	}

	return 0;
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDefederationClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = NULL;
}


GType
lasso_defederation_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDefederationClass),
			NULL, NULL, (GClassInitFunc) class_init, NULL, NULL,
			sizeof(LassoDefederation),
			0,
			NULL,
			NULL,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoDefederation", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_defederation_new:
 * @server: the #LassoServer
 *
 * Creates a new #LassoDefederation.
 *
 * Return value: a newly created #LassoDefederation object; or NULL if an error
 *     occured
 **/
LassoDefederation*
lasso_defederation_new(LassoServer *server)
{
	LassoDefederation *defederation;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	defederation = g_object_new(LASSO_TYPE_DEFEDERATION, NULL);
	LASSO_PROFILE(defederation)->server = g_object_ref(server);

	return defederation;
}
