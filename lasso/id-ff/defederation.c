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

#include <lasso/id-ff/defederation.h>

struct _LassoDefederationPrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_defederation_build_notification_msg:
 * @defederation: the federation termination object
 * 
 * This method builds the federation termination notification message.
 * 
 * It gets the federation termination notification protocol profile and:
 * 
 * - if it is a SOAP method, then it builds the federation termination
 *   notification SOAP message, optionaly signs the notification node, set the
 *   msg_body attribute, gets the SoapEndpoint url and set the msg_url
 *   attribute of the federation termination object.
 *
 * - if it is a HTTP-Redirect method, then it builds the federation termination
 *   notification QUERY message (optionaly signs the notification message),
 *   builds the federation termination notification url with federation
 *   termination service url, set the msg_url attribute of the federation
 *   termination object, set the msg_body to NULL
 * 
 * Return value: O of OK else < 0
 **/
gint
lasso_defederation_build_notification_msg(LassoDefederation *defederation)
{
	LassoProfile      *profile;
	LassoProvider     *remote_provider;
	gchar             *url = NULL, *query = NULL;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(defederation);

	/* get the remote provider object */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Provider %s not found", profile->remote_providerID);
		return -1;
	}

	/* get the protocol profile type */

	/* build the federation termination notification message (SOAP or HTTP-Redirect) */
	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		/* build the logout request message */
		profile->msg_url = lasso_provider_get_metadata_one(
				remote_provider, "SoapEndpoint");
		profile->msg_body = lasso_node_export_to_soap(profile->request,
				profile->server->private_key, profile->server->certificate);
	}
	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* build and optionaly sign the query message and build the
		 * federation termination notification url */
		url = lasso_provider_get_metadata_one(remote_provider,
				"FederationTerminationServiceURL");
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

		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		g_free(url);
		g_free(query);
		profile->msg_body = NULL;
	}

	if (profile->msg_url == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid http method");
		return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
	}

	return 0;
}

/**
 * lasso_defederation_destroy:
 * @defederation: the federation termination object
 * 
 * This method destroys the federation termination object
 *
 **/
void
lasso_defederation_destroy(LassoDefederation *defederation)
{
	g_object_unref(G_OBJECT(defederation));
}

/**
 * lasso_defederation_init_notification:
 * @defederation: the federation termination object
 * @remote_providerID: the provider id of the federation termination notified
 * provider.
 *
 * It sets a new federation termination notification to the remote provider id
 * with the provider id of the requester (from the server object )
 * and the name identifier of the federated principal
 * 
 * Return value: 0 if OK else < 0
 **/
gint
lasso_defederation_init_notification(LassoDefederation *defederation, gchar *remote_providerID,
		lassoHttpMethod http_method)
{
	LassoProfile*profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlNameIdentifier *nameIdentifier = NULL;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(defederation);

	/* set the remote provider id */
	profile->remote_providerID = g_strdup(remote_providerID);

	if (profile->remote_providerID == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				"No remote provider id to send the defederation request");
		return -1;
	}


	remote_provider = g_hash_table_lookup(
			profile->server->providers, profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Remote provider not found");
		return -1;
	}

	/* get federation */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (federation == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Federation not found for %s",
				profile->remote_providerID);
		return -1;
	}

	/* get the nameIdentifier to send the federation termination notification */
	nameIdentifier = lasso_profile_get_nameIdentifier(profile);
	if (nameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Name identifier not found for %s",
				profile->remote_providerID);
		return -1;
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
			message(G_LOG_LEVEL_CRITICAL, "This provider can't initiate this profile");
			return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	/* build the request */
	if (http_method == LASSO_HTTP_METHOD_SOAP) {
		profile->request = lasso_lib_federation_termination_notification_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_WITHX509,
				LASSO_SIGNATURE_METHOD_RSA_SHA1);
	}
	if (http_method == LASSO_HTTP_METHOD_REDIRECT) {
		profile->request = lasso_lib_federation_termination_notification_new_full(
				LASSO_PROVIDER(profile->server)->ProviderID,
				nameIdentifier,
				LASSO_SIGNATURE_TYPE_NONE,
				0);
	}
	if (LASSO_IS_LIB_FEDERATION_TERMINATION_NOTIFICATION(profile->request) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Error while building the request");
		return -1;
	}

	/* Set the nameIdentifier attribute from content local variable */
	profile->nameIdentifier = g_strdup(nameIdentifier->content);

	/* remove federation with remote provider id */
	if (profile->identity == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Identity not found");
		return -1;
	}
	lasso_identity_remove_federation(profile->identity, profile->remote_providerID);

	/* remove assertion from session */
	if (profile->session)
		lasso_session_remove_assertion(profile->session, profile->remote_providerID);

	/* Save notification method */
	profile->http_request_method = http_method;

	return 0;
}

/**
 * lasso_defederation_process_notification_msg:
 * @defederation: the federation termination object
 * @notification_msg: the federation termination notification message
 * 
 * Process the federation termination notification.
 * 
 * - if it is a SOAP notification method then it builds the federation
 *   termination object from the SOAP message and optionaly verify the
 *   signature.
 *
 * - if it is a HTTP-Redirect notification method then it builds the
 *   federation termination notication object from the QUERY message and
 *   optionaly verify the signature.
 * 
 * Set the msg_nameIdentifier attribute with the NameIdentifier content of the
 * notification object and optionaly set the msg_relayState attribute with the
 * RelayState content of the notification object
 *
 * Return value: 0 on success or a negative value otherwise.
 **/
gint
lasso_defederation_process_notification_msg(LassoDefederation *defederation, char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_DEFEDERATION(defederation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(defederation);

	profile->request = lasso_lib_federation_termination_notification_new();
	format = lasso_node_init_from_message(profile->request, request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}

	profile->remote_providerID = g_strdup(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
				profile->request)->ProviderID);
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Unknown provider");
		return -1;
	}

	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "RequestID");

	/* set the http request method */
	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;

	profile->nameIdentifier = g_strdup(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
				profile->request)->NameIdentifier->content);

	/* get the RelayState (only available in redirect mode) */
	if (LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(profile->request)->RelayState)
		profile->msg_relayState = g_strdup(
				LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
					profile->request)->RelayState);

	return profile->signature_status;
}

/**
 * lasso_defederation_validate_notification:
 * @defederation: the federation termination object
 * 
 * Validate the federation termination notification :
 * -  verifies the ProviderID
 * -  if HTTP-Redirect method, set msg_url with the federation termination
 *    service return url
 * -  verifies the federation
 * -  verifies the authentication
 * 
 * Return value: O if OK else < 0
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
	profile->msg_url = NULL;
	profile->msg_body = NULL;

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		remote_provider = g_hash_table_lookup(profile->server->providers,
				profile->remote_providerID);
		if (remote_provider == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Provider not found");
			return -1;
		}

		/* build the QUERY and the url. Dont need to sign the query,
		 * only the relay state is optinaly added and it is crypted
		 * by the notifier */
		profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
				"FederationTerminationServiceReturnURL");
		if (profile->msg_url == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Unknown profile service return URL");
			return -1;
		}

		/* if a relay state, then build the query part */
		if (profile->msg_relayState) {
			gchar *url;
			url = g_strdup_printf("%s?RelayState=%s",
					profile->msg_url, profile->msg_relayState);
			g_free(profile->msg_url);
			profile->msg_url = url;
		}
	}

	/* get the name identifier */
	nameIdentifier = LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(
			profile->request)->NameIdentifier;
	if (nameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in request");
		return -1;
	}

	/* Verify federation */
	if (profile->identity == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Identity not found");
		return -1;
	}

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (federation == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Federation not found");
		return -1;
	}

	if (lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "No name identifier for %s",
				profile->remote_providerID);
		return -1;
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
/* overridden parent class methods                                            */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoDefederation *defederation = LASSO_DEFEDERATION(object);
	if (defederation->private_data->dispose_has_run == TRUE) {
		return;
	}
	defederation->private_data->dispose_has_run = TRUE;
	debug("Defederation object 0x%x disposed ...", defederation);

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoDefederation *defederation = LASSO_DEFEDERATION(object);
	debug("Defederation object 0x%x finalized ...", defederation);
	g_free(defederation->private_data);
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDefederation *defederation)
{
	defederation->private_data = g_new(LassoDefederationPrivate, 1);
	defederation->private_data->dispose_has_run = FALSE;
}

static void
class_init(LassoDefederationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	/* no dump needed
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	*/

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_defederation_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDefederationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDefederation),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoDefederation", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_defederation_new:
 * @server: the server object of the provider
 * @provider_type: the provider type (service provider or identity provider)
 * 
 * This function build a new federation termination object to build
 * a notification message or to process a notification.
 *
 * If building a federation termination notification message then call :
 *    lasso_defederation_init_notification()
 *    lasso_defederation_build_notification_msg()
 * and get msg_url or msg_body.
 *
 * If processing a federation termination notification message then call :
 *   lasso_defederation_process_notification_msg()
 *   lasso_defederation_validate_notification()
 * and process the returned code.
 *
 * Return value: a new instance of federation termination object or NULL
 **/
LassoDefederation*
lasso_defederation_new(LassoServer *server)
{
	LassoDefederation *defederation;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	defederation = g_object_new(LASSO_TYPE_DEFEDERATION, NULL);
	LASSO_PROFILE(defederation)->server = server;

	return defederation;
}

