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

#include <lasso/saml-2.0/name_id_management.h>
#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/saml-2.0/profileprivate.h>
#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/profileprivate.h>
#include <lasso/id-ff/identityprivate.h>
#include <lasso/id-ff/serverprivate.h>
#include <lasso/xml/xml_enc.h>

/**
 * SECTION:name_id_management
 * @short_description: Name Id Management Profile (SAMLv2)
 *
 **/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_name_id_management_init_request:
 * @name_id_management: a #LassoNameIdManagement
 * @remote_provider_id: the providerID of the remote provider.
 * @new_name_id: the new NameId or NULL to terminate a federation
 * @http_method: if set, then it get the protocol profile in metadata
 *     corresponding of this HTTP request method.
 *
 * Initializes a new Name Id Management Request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_init_request(LassoNameIdManagement *name_id_management,
		char *remote_provider_id,
		char *new_name_id,
		LassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSaml2NameID *name_id, *name_id_n;
	LassoSamlp2RequestAbstract *request;
	LassoSession *session = NULL;
	LassoNode *oldNameIdentifier;

	g_return_val_if_fail(LASSO_IS_NAME_ID_MANAGEMENT(name_id_management),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(name_id_management);

	/* verify if the identity */
	if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	/* set the remote provider id */
	g_free (profile->remote_providerID);
	if (remote_provider_id == NULL) {
		/* verify if session exists */
		session = lasso_profile_get_session(profile);
		if (session == NULL) {
			return critical_error(LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
		}
		profile->remote_providerID = lasso_session_get_provider_index(session, 0);
	} else {
		profile->remote_providerID = g_strdup(remote_provider_id);
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* Get federation */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}

	/* get the current NameID */
	name_id_n = LASSO_SAML2_NAME_ID(lasso_profile_get_nameIdentifier(profile));
	name_id = LASSO_SAML2_NAME_ID(name_id_n);
	oldNameIdentifier = profile->nameIdentifier;
	if (federation->local_nameIdentifier) {
		profile->nameIdentifier = g_object_ref(federation->local_nameIdentifier);
	} else {
		profile->nameIdentifier = g_object_ref(name_id_n);
	}
	if (oldNameIdentifier != NULL) 
		g_object_unref(oldNameIdentifier);

	/* XXX: check HTTP method is supported */

	profile->request = lasso_samlp2_manage_name_id_request_new();

	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	request->ID = lasso_build_unique_id(32);
	request->Version = g_strdup("2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(request)->NameID = g_object_ref( \
			profile->nameIdentifier);

	if (new_name_id) {
		LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(request)->NewID = g_strdup(new_name_id);
	} else {
		LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(request)->Terminate = \
				LASSO_SAMLP2_TERMINATE(lasso_samlp2_terminate_new());
	}
	
	profile->http_request_method = http_method;

	return 0;
}


/**
 * lasso_name_id_management_build_request_msg:
 * @name_id_management: a #LassoNameIdManagement
 *
 * Builds the Name Id Management request message.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_build_request_msg(LassoNameIdManagement *name_id_management)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_NAME_ID_MANAGEMENT(name_id_management),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(name_id_management);
	lasso_profile_clean_msg_info(profile);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
				"ManageNameIDService SOAP");
	 	/* XXX set private key so message is signed */
		profile->msg_body = lasso_node_export_to_soap(profile->request);
		return 0;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		char *url, *query;
		url = lasso_provider_get_metadata_one(remote_provider,
				"ManageNameIDService HTTP-Redirect");
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
		profile->msg_body = NULL;
		g_free(url);
		g_free(query);
		return 0;
	}

	/* XXX: Artifact profile support */

	return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
}


/**
 * lasso_name_id_management_process_request_msg:
 * @name_id_management: a #LassoNameIdManagement
 * @request_msg: the Name Id Management request message
 * 
 * Processes a Name Id Management request message.  Rebuilds a request object
 * from the message and check its signature.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_process_request_msg(LassoNameIdManagement *name_id_management,
		char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;
	LassoSaml2NameID *name_id;
	LassoSaml2EncryptedElement *encrypted_id;
	LassoSaml2EncryptedElement* encrypted_element = NULL;
	xmlSecKey *encryption_private_key = NULL;

	g_return_val_if_fail(LASSO_IS_NAME_ID_MANAGEMENT(name_id_management),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, 
			LASSO_PARAM_ERROR_INVALID_VALUE);
	
	profile = LASSO_PROFILE(name_id_management);
	profile->request = lasso_samlp2_manage_name_id_request_new();
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

	name_id = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NameID;
	encrypted_id = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->EncryptedID;

	if (name_id == NULL && encrypted_id != NULL) {
		encryption_private_key = profile->server->private_data->encryption_private_key;
		encrypted_element = LASSO_SAML2_ENCRYPTED_ELEMENT(encrypted_id);
		if (encrypted_element != NULL && encryption_private_key == NULL) {
			return LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY;
		}
		if (encrypted_element != NULL && encryption_private_key != NULL) {
			profile->nameIdentifier = LASSO_NODE(lasso_node_decrypt(
				encrypted_id, encryption_private_key));
			LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NameID = \
				LASSO_SAML2_NAME_ID(profile->nameIdentifier);
			LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->EncryptedID = NULL;

		}
	} else {
		profile->nameIdentifier = g_object_ref(name_id);
	}

	return profile->signature_status;
}


/**
 * lasso_name_id_management_validate_request:
 * @name_id_management: a #LassoNameIdManagement
 * 
 * Processes a Name Id Management request, performing requested actions against
 * principal federations.  Profile identity may have to be saved afterwards.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_name_id_management_validate_request(LassoNameIdManagement *name_id_management)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlp2StatusResponse *response;
	LassoSaml2NameID *name_id;

	g_return_val_if_fail(LASSO_IS_NAME_ID_MANAGEMENT(name_id_management),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(name_id_management);

	if (LASSO_IS_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request) == FALSE)
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;

	if (profile->identity == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}
	
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

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
	}

	if (profile->response) {
		lasso_node_destroy(profile->response);
	}

	profile->response = lasso_samlp2_manage_name_id_response_new();
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
	name_id = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NameID;
	if (name_id == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				"Name identifier not found in name id management request");
		/* XXX: which status code in SAML 2.0 ? */
		lasso_saml20_profile_set_response_status(
				profile, LASSO_SAML2_STATUS_CODE_UNKNOWN_PRINCIPAL);
		return LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
	}

	if (LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->Terminate) {
		/* defederation */
		lasso_identity_remove_federation(profile->identity, profile->remote_providerID);
	} else {
		/* name registration */
		LassoSaml2NameID *new_name_id;
		new_name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
		new_name_id->Format = g_strdup(name_id->Format);
		new_name_id->NameQualifier = g_strdup(name_id->NameQualifier);
		new_name_id->SPNameQualifier = g_strdup(name_id->SPNameQualifier);
		if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
			/* if the requester is the service provider, the new
			 * identifier MUST appear in subsequent <NameID>
			 * elements in the SPProvidedID attribute
			 *  -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->SPProvidedID = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
			new_name_id->content = g_strdup(name_id->content);
		} else {
			/* If the requester is the identity provider, the new
			 * value will appear in subsequent <NameID> elements as
			 * the element's content.
			 * -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->content = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
		}

		if (federation->local_nameIdentifier)
			lasso_node_destroy(LASSO_NODE(federation->local_nameIdentifier));
		federation->local_nameIdentifier = g_object_ref(new_name_id);
		profile->identity->is_dirty = TRUE;
	}

	return 0;
}

/**
 * lasso_name_id_management_build_response_msg:
 * @name_id_management: a #LassoNameIdManagement
 * 
 * Builds the Name Id Management response message.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_name_id_management_build_response_msg(LassoNameIdManagement *name_id_management)
{
	LassoProfile *profile;
	LassoSamlp2StatusResponse *response;
	LassoProvider *provider;
	char *url, *query;

	g_return_val_if_fail(LASSO_IS_NAME_ID_MANAGEMENT(name_id_management),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(name_id_management);
	lasso_profile_clean_msg_info(profile);

	if (profile->response == NULL) {
		/* no response set here means request denied */
		profile->response = lasso_samlp2_manage_name_id_response_new();
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
		return 0;
	}

	if (profile->remote_providerID == NULL || profile->response == NULL) {
		/* no remote provider id set or no response set, this means
		 * this function got called before validate_request, probably
		 * because there were no identity or federation */
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
				"ManageNameIDService HTTP-Redirect ResponseLocation");
		if (url == NULL) {
			url = lasso_provider_get_metadata_one(provider,
					"ManageNameIDService HTTP-Redirect");
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
		profile->msg_url = lasso_concat_url_query(url, query);
		profile->msg_body = NULL;
		g_free(url);
		g_free(query);
		return 0;
	}

	return LASSO_PROFILE_ERROR_MISSING_REQUEST;
}


/**
 * lasso_name_id_management_process_response_msg:
 * @name_id_management: a #LassoNameIdManagement
 * @response_msg: the response message
 * 
 * Parses the response message and builds the corresponding response object.
 * Performs requested actions against principal federations.  Profile identity
 * may have to be saved afterwards.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_process_response_msg(
		LassoNameIdManagement *name_id_management,
		gchar *response_msg)
{
	LassoProfile *profile;
	LassoHttpMethod response_method;
	LassoProvider *remote_provider;
	LassoSamlp2StatusResponse *response;
	LassoMessageFormat format;
	char *status_code_value;
	int rc;

	g_return_val_if_fail(LASSO_IS_NAME_ID_MANAGEMENT(name_id_management),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(name_id_management);

	if (LASSO_IS_SAMLP2_MANAGE_NAME_ID_RESPONSE(profile->response) == TRUE) {
		lasso_node_destroy(profile->response);
		profile->response = NULL;
	}

	profile->response = lasso_samlp2_manage_name_id_response_new();
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
		/* XXX: is signature mandatory ? */
		message(G_LOG_LEVEL_WARNING, "No signature on response");
		rc = 0;
	}

	response = LASSO_SAMLP2_STATUS_RESPONSE(profile->response);

	if (response->Status == NULL || response->Status->StatusCode == NULL
			|| response->Status->StatusCode->Value == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "No Status in ManageNameIDResponse !");
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}
	status_code_value = response->Status->StatusCode->Value;

	if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "Status code is not success: %s", status_code_value);
		return LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;
	}

	if (LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->Terminate) {
		lasso_identity_remove_federation(profile->identity, profile->remote_providerID);
	} else {
		LassoSaml2NameID *new_name_id, *name_id;
		LassoFederation *federation;

		name_id = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NameID;

		new_name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
		new_name_id->Format = g_strdup(name_id->Format);
		new_name_id->NameQualifier = g_strdup(name_id->NameQualifier);
		new_name_id->SPNameQualifier = g_strdup(name_id->SPNameQualifier);
		if (LASSO_PROVIDER(profile->server)->role == LASSO_PROVIDER_ROLE_SP) {
			/* if the requester is the service provider, the new
			 * identifier MUST appear in subsequent <NameID>
			 * elements in the SPProvidedID attribute
			 *  -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->SPProvidedID = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
			new_name_id->content = g_strdup(name_id->content);
		} else {
			/* If the requester is the identity provider, the new
			 * value will appear in subsequent <NameID> elements as
			 * the element's content.
			 * -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->content = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
		}

		/* Get federation */
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (LASSO_IS_FEDERATION(federation) == FALSE) {
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		}

		if (federation->local_nameIdentifier)
			lasso_node_destroy(LASSO_NODE(federation->local_nameIdentifier));
		federation->local_nameIdentifier = g_object_ref(new_name_id);
		profile->identity->is_dirty = TRUE;

	}

	return 0;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)"NameIdManagement");
	xmlSetProp(xmlnode, (xmlChar*)"NameIdManagementDumpVersion", (xmlChar*)"1");

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
	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{  
	G_OBJECT_CLASS(parent_class)->finalize(object);
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoNameIdManagement *name_id_management)
{
}

static void
class_init(LassoNameIdManagementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "NameIdManagement");
	lasso_node_class_add_snippets(nclass, schema_snippets);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}



GType
lasso_name_id_management_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoNameIdManagementClass),
			NULL, NULL, 
			(GClassInitFunc) class_init,
			NULL, NULL,
			sizeof(LassoNameIdManagement),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoNameIdManagement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_name_id_management_new:
 * @server: the #LassoServer
 * 
 * Creates a new #LassoNameIdManagement.
 *
 * Return value: a newly created #LassoNameIdManagement object; or NULL if an error
 *     occured
 **/
LassoNameIdManagement*
lasso_name_id_management_new(LassoServer *server)
{
	LassoNameIdManagement *name_id_management;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	name_id_management = g_object_new(LASSO_TYPE_NAME_ID_MANAGEMENT, NULL);
	LASSO_PROFILE(name_id_management)->server = g_object_ref(server);

	return name_id_management;
}

/**
 * lasso_name_id_management_destroy:
 * @name_id_management: a #LassoNameIdManagement
 * 
 * Destroys a #LassoNameIdManagement object.
 **/
void
lasso_name_id_management_destroy(LassoNameIdManagement *name_id_management)
{
	lasso_node_destroy(LASSO_NODE(name_id_management));
}

/**
 * lasso_name_id_management_new_from_dump:
 * @server: the #LassoServer
 * @dump: XML name_id_management dump
 *
 * Restores the @dump to a new #LassoLogout.
 *
 * Return value: a newly created #LassoLogout; or NULL if an error occured
 **/
LassoNameIdManagement*
lasso_name_id_management_new_from_dump(LassoServer *server, const char *dump)
{
	LassoNameIdManagement *name_id_management;
	xmlDoc *doc;

	if (dump == NULL)
		return NULL;

	name_id_management = lasso_name_id_management_new(g_object_ref(server));
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(name_id_management), xmlDocGetRootElement(doc)); 
	xmlFreeDoc(doc);

	return name_id_management;
}

/**
 * lasso_name_id_management_dump:
 * @name_id_management: a #LassoLogout
 *
 * Dumps @name_id_management content to an XML string.
 *
 * Return value: the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_name_id_management_dump(LassoNameIdManagement *name_id_management)
{
	return lasso_node_dump(LASSO_NODE(name_id_management));
}
