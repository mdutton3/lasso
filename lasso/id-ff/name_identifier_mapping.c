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

#include <lasso/id-ff/name_identifier_mapping.h>

#include <lasso/id-ff/providerprivate.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_name_identifier_mapping_build_request_msg(LassoNameIdentifierMapping *mapping)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);

	profile = LASSO_PROFILE(mapping);

	/* get provider object */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				profile->remote_providerID);
	}

	if (remote_provider->role != LASSO_PROVIDER_ROLE_IDP) {
		message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden at IDP");
		return LASSO_ERROR_UNDEFINED;
	}

	profile->msg_url = lasso_provider_get_metadata_one(remote_provider, "SoapEndpoint");
	if (profile->msg_url == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	profile->request->private_key_file = profile->server->private_key;
	profile->request->certificate_file = profile->server->certificate;
	profile->msg_body = lasso_node_export_to_soap(LASSO_NODE(profile->request));
	if (profile->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}

gint
lasso_name_identifier_mapping_build_response_msg(LassoNameIdentifierMapping *mapping)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);

	profile = LASSO_PROFILE(mapping);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				profile->remote_providerID);
	}

	if (remote_provider->role != LASSO_PROVIDER_ROLE_SP) {
		message(G_LOG_LEVEL_CRITICAL, "Build response msg method is forbidden at SP");
		return LASSO_ERROR_UNDEFINED;
	}

	/* verify the provider type is a service provider type */
	/* build name identifier mapping response msg */
	if (profile->http_request_method != LASSO_HTTP_METHOD_SOAP) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	profile->msg_url = NULL;
	profile->response->private_key_file = profile->server->private_key;
	profile->response->certificate_file = profile->server->certificate;
	profile->msg_body = lasso_node_export_to_soap(LASSO_NODE(profile->response));

	return 0;
}


/**
 * lasso_name_identifier_mapping_destroy:
 * @mapping: a #LassoNameIdentifierMapping
 * 
 * Destroys a #LassoNameIdentifierMapping object.
 **/
void
lasso_name_identifier_mapping_destroy(LassoNameIdentifierMapping *mapping)
{
	lasso_node_destroy(LASSO_NODE(mapping));
}

gint
lasso_name_identifier_mapping_init_request(LassoNameIdentifierMapping *mapping,
		char *targetNamespace, char *remote_providerID)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlNameIdentifier *nameIdentifier;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(targetNamespace != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(mapping);

	/* verify if the identity exists */
	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	/* set the remote provider id */
	if (remote_providerID == NULL)
		g_assert_not_reached(); /* was default; didn't make sense */
	profile->remote_providerID = g_strdup(remote_providerID);

	/* verify the provider type is a service provider type */
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				profile->remote_providerID);
	}
	if (remote_provider->role != LASSO_PROVIDER_ROLE_IDP) {
		message(G_LOG_LEVEL_CRITICAL, "Init request method is forbidden for an IDP");
		return LASSO_ERROR_UNDEFINED;
	}

	/* get federation */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (federation == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}

	/* name identifier */
	nameIdentifier = federation->local_nameIdentifier;
	if (nameIdentifier == NULL)
		nameIdentifier = federation->remote_nameIdentifier;
	if (nameIdentifier == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND);
	}

	/* get / verify http method */
	profile->http_request_method = LASSO_HTTP_METHOD_NONE;
	if (lasso_provider_accept_http_method(LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_NAME_IDENTIFIER_MAPPING,
				LASSO_HTTP_METHOD_REDIRECT, TRUE) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
	}

	profile->request = lasso_lib_name_identifier_mapping_request_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			nameIdentifier,
			targetNamespace,
			LASSO_SIGNATURE_TYPE_WITHX509,
			LASSO_SIGNATURE_METHOD_RSA_SHA1);
	if (LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	profile->http_request_method = LASSO_HTTP_METHOD_SOAP;

	return 0;
}

gint
lasso_name_identifier_mapping_process_request_msg(LassoNameIdentifierMapping *mapping,
		char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(mapping);

	/* build name identifier mapping from message */
	profile->request = lasso_lib_name_identifier_mapping_request_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->request), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request)->ProviderID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(
					profile->request)->ProviderID);
	}
	profile->remote_providerID = g_strdup(remote_provider->ProviderID);

	/* verify http method is supported */
	if (lasso_provider_accept_http_method(LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_NAME_IDENTIFIER_MAPPING,
				LASSO_HTTP_METHOD_REDIRECT, FALSE) == FALSE ) {
		return critical_error(LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE);
	}

	/* verify signature */
	profile->signature_status = lasso_provider_verify_signature(
			remote_provider, request_msg, "RequestID", format);

	profile->http_request_method = LASSO_HTTP_METHOD_SOAP;

	profile->nameIdentifier = g_object_ref(LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(
			profile->request)->NameIdentifier);

	return profile->signature_status;
}

gint
lasso_name_identifier_mapping_process_response_msg(LassoNameIdentifierMapping *mapping,
		char *response_msg)
{
	LassoProfile  *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;
	int rc;
	char *statusCodeValue;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(mapping);

	profile->response = lasso_lib_name_identifier_mapping_response_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->response), response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response)->ProviderID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				profile->remote_providerID);
	}

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ResponseID", format);

	statusCodeValue = LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(
			profile->response)->Status->StatusCode->Value;
	if (strcmp(statusCodeValue, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "%s", statusCodeValue);
		return LASSO_ERROR_UNDEFINED;
	}

	/* Set the target name identifier */
	mapping->targetNameIdentifier = g_strdup(LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(
			profile->request)->NameIdentifier->content);

	return rc;
}

gint
lasso_name_identifier_mapping_validate_request(LassoNameIdentifierMapping *mapping)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoLibNameIdentifierMappingRequest *request;
	LassoSamlNameIdentifier *nameIdentifier, *targetNameIdentifier;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping) == TRUE,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_PROFILE(mapping);

	/* verify the provider type is a service provider type */
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}
	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND,
				profile->remote_providerID);
	}

	if (remote_provider->role != LASSO_PROVIDER_ROLE_SP) {
		message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden at SP");
		return LASSO_ERROR_UNDEFINED;
	}

	/* verify request attribute of mapping is a name identifier mapping request */
	if (LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid NameIdentifierMappingRequest");
		return LASSO_ERROR_UNDEFINED;
	}

	if (profile->http_request_method != LASSO_HTTP_METHOD_SOAP) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	request = LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request);

	profile->response = lasso_lib_name_identifier_mapping_response_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_SAML_STATUS_CODE_SUCCESS,
			request,
			LASSO_SIGNATURE_TYPE_WITHX509,
			LASSO_SIGNATURE_METHOD_RSA_SHA1);

	if (LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED);
	}

	/* verify signature status */
	if (profile->signature_status != 0) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE);
	}

	/* Verify identity attribute of mapping object */
	if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	/* verify federation of the SP request */
	federation = g_hash_table_lookup(
			profile->identity->federations, profile->remote_providerID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}
	nameIdentifier = federation->remote_nameIdentifier;
	if (nameIdentifier == NULL)
		nameIdentifier = federation->local_nameIdentifier;

	if (nameIdentifier == NULL) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
		message(G_LOG_LEVEL_CRITICAL, "Name identifier of federation not found");
		return LASSO_ERROR_UNDEFINED;
	}

	/* get the federation of the target name space and his name identifier */
	if (request->TargetNamespace == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Target name space not found");
		return LASSO_ERROR_UNDEFINED;
	}
	federation = g_hash_table_lookup(profile->identity->federations, request->TargetNamespace);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		message(G_LOG_LEVEL_CRITICAL, "Target name space federation not found");
		return LASSO_ERROR_UNDEFINED;
	}

	targetNameIdentifier = federation->remote_nameIdentifier;
	if (targetNameIdentifier == NULL) {
		targetNameIdentifier = federation->local_nameIdentifier;
	}

	if (targetNameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				"Name identifier for target name space federation not found");
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_ERROR_UNDEFINED;
	}

	LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response)->NameIdentifier =
		g_object_ref(targetNameIdentifier);

	return 0;
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoNameIdentifierMapping *name_identifier_mapping)
{
}

static void
class_init(LassoNameIdentifierMappingClass *klass)
{
}

GType
lasso_name_identifier_mapping_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoNameIdentifierMappingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoNameIdentifierMapping),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoNameIdentifierMapping", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_name_identifier_mapping_new
 * @server: the #LassoServer
 *
 * Creates a new #LassoNameIdentifierMapping.
 *
 * Return value: a newly created #LassoNameIdentifierMapping object; or NULL
 *     if an error occured
 **/
LassoNameIdentifierMapping *
lasso_name_identifier_mapping_new(LassoServer *server)
{
	LassoNameIdentifierMapping *mapping = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	mapping = g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING, NULL);
	LASSO_PROFILE(mapping)->server = g_object_ref(server);

	return mapping;
}

LassoNameIdentifierMapping*
lasso_name_identifier_mapping_new_from_dump(LassoServer *server, const char *dump)
{
	g_assert_not_reached();
	return NULL;
}

char*
lasso_name_identifier_mapping_dump(LassoNameIdentifierMapping *mapping)
{
	g_assert_not_reached();
	return lasso_node_dump(LASSO_NODE(mapping));
}

