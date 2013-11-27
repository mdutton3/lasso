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
 * SECTION:name_identifier_mapping
 * @short_description: Liberty Enabled Client and Proxy Profile (ID-FF)
 *
 **/

#include "../utils.h"
#include "../xml/private.h"
#include "name_identifier_mapping.h"

#include "profileprivate.h"
#include "providerprivate.h"

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_name_identifier_mapping_build_request_msg:
 * @mapping: a #LassoNameIdentifierMapping
 *
 * Builds a name identifier mapping request message.
 *
 * <itemizedlist>
 * <listitem><para>
 *   If it is a SOAP method, then it builds the request as a SOAP message,
 *   optionally signs his node, sets @msg_body with that message and sets
 *   @msg_url with the SOAP Endpoint URL
 * </para></listitem>
 * <listitem><para>
 *   If it is a HTTP-Redirect method, then it builds the request as a query
 *   string message, optionally signs it and sets @msg_url to that URL.
 * </para></listitem>
 * </itemizedlist>
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_identifier_mapping_build_request_msg(LassoNameIdentifierMapping *mapping)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(mapping);
	lasso_profile_clean_msg_info(profile);

	if (profile->remote_providerID == NULL) {
		/* this means lasso_name_identifer_mapping_init_request was not called before */
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	/* get provider object */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	if (remote_provider->role != LASSO_PROVIDER_ROLE_IDP) {
		message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden at IDP");
		return LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE;
	}

	profile->msg_url = lasso_provider_get_metadata_one(remote_provider, "SoapEndpoint");
	if (profile->msg_url == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->private_key_file =
		profile->server->private_key;
	LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->certificate_file =
		profile->server->certificate;
	profile->msg_body = lasso_node_export_to_soap(profile->request);
	if (profile->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}


/**
 * lasso_name_identifier_mapping_build_response_msg:
 * @mapping: a #LassoNameIdentifierMapping
 *
 * Builds a name identifier mapping response message.
 *
 * <itemizedlist>
 * <listitem><para>
 *   If it is a SOAP method, then it builds the response as a SOAP message,
 *   optionally signs his node, sets @msg_body with that message and sets
 *   @msg_url with the register name identifier service return URL.
 * </para></listitem>
 * <listitem><para>
 *   If it is a HTTP-Redirect method, then it builds the response as a query
 *   string message, optionally signs it and sets @msg_url to that URL.
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
lasso_name_identifier_mapping_build_response_msg(LassoNameIdentifierMapping *mapping)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(mapping);
	lasso_profile_clean_msg_info(profile);

	if (profile->remote_providerID == NULL) {
		/* this means lasso_name_identifer_mapping_init_request was not called before */
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	if (remote_provider->role != LASSO_PROVIDER_ROLE_SP) {
		message(G_LOG_LEVEL_CRITICAL, "Build response msg method is forbidden at SP");
		return LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE;
	}

	/* verify the provider type is a service provider type */
	/* build name identifier mapping response msg */
	if (profile->http_request_method != LASSO_HTTP_METHOD_SOAP) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	profile->msg_url = NULL;
	LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->private_key_file =
		profile->server->private_key;
	LASSO_SAMLP_RESPONSE_ABSTRACT(profile->response)->certificate_file =
		profile->server->certificate;
	profile->msg_body = lasso_node_export_to_soap(profile->response);

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


/**
 * lasso_name_identifier_mapping_init_request:
 * @mapping: a #LassoNameIdentifierMapping
 * @targetNamespace: the request targetNamespace
 * @remote_providerID: the providerID of the identity provider.
 *
 * Initializes a new lib:NameIdentifierMappingRequest request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
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
	g_return_val_if_fail(targetNamespace != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(remote_providerID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(mapping);

	/* verify if the identity exists */
	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	/* set the remote provider id */
	profile->remote_providerID = g_strdup(remote_providerID);

	/* verify the provider type is a service provider type */
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}
	if (remote_provider->role != LASSO_PROVIDER_ROLE_IDP) {
		message(G_LOG_LEVEL_CRITICAL, "Init request method is forbidden for an IDP");
		return LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE;
	}

	/* get federation */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (federation == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}

	/* name identifier */
	nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier);
	if (nameIdentifier == NULL)
		nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(federation->remote_nameIdentifier);
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
			profile->server->certificate ?
				LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
			LASSO_SIGNATURE_METHOD_RSA_SHA1);
	if (LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	if (lasso_provider_get_protocol_conformance(remote_provider) < LASSO_PROTOCOL_LIBERTY_1_2) {
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MajorVersion = 1;
		LASSO_SAMLP_REQUEST_ABSTRACT(profile->request)->MinorVersion = 1;
	}

	profile->http_request_method = LASSO_HTTP_METHOD_SOAP;

	return 0;
}


/**
 * lasso_name_identifier_mapping_process_request_msg:
 * @mapping: a #LassoNameIdentifierMapping
 * @request_msg: the name identifier mapping request message
 *
 * Processes a lib:NameIdentifierMappingRequest message.  Rebuilds a request
 * object from the message and optionally verifies its signature.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_identifier_mapping_process_request_msg(LassoNameIdentifierMapping *mapping,
		char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(mapping);

	/* build name identifier mapping from message */
	profile->request = lasso_lib_name_identifier_mapping_request_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->request), request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
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


/**
 * lasso_name_identifier_mapping_process_response_msg:
 * @mapping: a #LassoNameIdentifierMapping
 * @response_msg: the name identifier mapping response message
 *
 * Processes a lib:NameIdentifierMappingResponse message.  Rebuilds a response
 * object from the message and optionally verifies its signature.
 *
 * If the response depicts Success it will also sets @targetNameIdentifier.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_identifier_mapping_process_response_msg(LassoNameIdentifierMapping *mapping,
		char *response_msg)
{
	LassoProfile  *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;
	LassoLibNameIdentifierMappingResponse *response;
	int rc = 0;
	char *statusCodeValue;

	g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(mapping);

	profile->response = lasso_lib_name_identifier_mapping_response_new();
	format = lasso_node_init_from_message(LASSO_NODE(profile->response), response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	response = LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response);

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ResponseID", format);

	if (response->Status == NULL || response->Status->StatusCode == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}

	statusCodeValue = response->Status->StatusCode->Value;
	if (statusCodeValue == NULL || strcmp(statusCodeValue,
				LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		return LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;
	}


	/* Set the target name identifier */
	if (LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request)->NameIdentifier) {
		mapping->targetNameIdentifier = g_strdup(LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(
					profile->request)->NameIdentifier->content);
	} else {
		mapping->targetNameIdentifier = NULL;
		return LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_IDENTIFIER;
	}

	return rc;
}


/**
 * lasso_name_identifier_mapping_validate_request:
 * @mapping: a #LassoNameIdentifierMapping
 *
 * Checks profile request with regards to message status and principal
 * federations, update them accordingly and prepares a
 * lib:NameIdentifierMappingResponse accordingly.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
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
	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (remote_provider == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	if (remote_provider->role != LASSO_PROVIDER_ROLE_SP) {
		message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden at SP");
		return LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE;
	}

	/* verify request attribute of mapping is a name identifier mapping request */
	if (LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid NameIdentifierMappingRequest");
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}

	if (profile->http_request_method != LASSO_HTTP_METHOD_SOAP) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
	}

	request = LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request);

	profile->response = lasso_lib_name_identifier_mapping_response_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_SAML_STATUS_CODE_SUCCESS,
			request,
			profile->server->certificate ?
				LASSO_SIGNATURE_TYPE_WITHX509 : LASSO_SIGNATURE_TYPE_SIMPLE,
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
	nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(federation->remote_nameIdentifier);
	if (nameIdentifier == NULL)
		nameIdentifier = LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier);

	if (nameIdentifier == NULL) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL);
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
	}

	/* get the federation of the target name space and his name identifier */
	if (request->TargetNamespace == NULL) {
		return LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_NAMESPACE;
	}
	federation = g_hash_table_lookup(profile->identity->federations, request->TargetNamespace);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		message(G_LOG_LEVEL_CRITICAL, "Target name space federation not found");
		return LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND;
	}

	targetNameIdentifier = LASSO_SAML_NAME_IDENTIFIER(federation->remote_nameIdentifier);
	if (targetNameIdentifier == NULL) {
		targetNameIdentifier = LASSO_SAML_NAME_IDENTIFIER(federation->local_nameIdentifier);
	}

	if (targetNameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				"Name identifier for target name space federation not found");
		lasso_profile_set_response_status(profile,
				LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST);
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
	}

	LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response)->NameIdentifier =
		g_object_ref(targetNameIdentifier);

	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoNameIdentifierMappingClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "NameIdentifierMapping");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
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
			(GClassInitFunc)class_init,
			NULL,
			NULL,
			sizeof(LassoNameIdentifierMapping),
			0,
			NULL,
			NULL
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
