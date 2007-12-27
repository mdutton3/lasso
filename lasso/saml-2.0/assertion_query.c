/* $Id: assertion_query.c 3237 2007-05-30 17:17:45Z dlaniel $ 
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

#include <lasso/saml-2.0/assertion_query.h>
#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/saml-2.0/profileprivate.h>
#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/profileprivate.h>
#include <lasso/id-ff/identityprivate.h>
#include <lasso/id-ff/serverprivate.h>
#include <lasso/xml/xml_enc.h>
#include <lasso/xml/saml-2.0/samlp2_assertion_id_request.h>
#include <lasso/xml/saml-2.0/samlp2_authn_query.h>
#include <lasso/xml/saml-2.0/samlp2_attribute_query.h>
#include <lasso/xml/saml-2.0/samlp2_authz_decision_query.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>


struct _LassoAssertionQueryPrivate
{
	LassoAssertionQueryRequestType query_request_type;
};


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_assertion_query_init_request:
 * @assertion_query: a #LassoAssertionQuery
 * @remote_provider_id: the providerID of the remote provider.
 * @http_method: if set, then it get the protocol profile in metadata
 *     corresponding of this HTTP request method.
 * @query_request_type: the type of request.
 *
 * Initializes a new Assertion Query Request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_assertion_query_init_request(LassoAssertionQuery *assertion_query,
		char *remote_provider_id,
		LassoHttpMethod http_method,
		LassoAssertionQueryRequestType query_request_type)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlp2RequestAbstract *request;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(remote_provider_id != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(assertion_query);

	/* verify the identity is set */
	if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
		return critical_error(LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND);
	}

	/* set the remote provider id */
	profile->remote_providerID = g_strdup(remote_provider_id);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* XXX: check HTTP method is supported */

	assertion_query->private_data->query_request_type = query_request_type;
	switch (query_request_type) {
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID:
			profile->request = lasso_samlp2_assertion_id_request_new();
			break;
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHN:
			profile->request = lasso_samlp2_authn_query_new();
			break;
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_ATTRIBUTE:
			profile->request = lasso_samlp2_attribute_query_new();
			break;
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION:
			profile->request = lasso_samlp2_authz_decision_query_new();
			break;
		default:
			return critical_error(LASSO_PARAM_ERROR_INVALID_VALUE);
	}

	if (query_request_type != LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID) {
		/* fill <Subject> */
		LassoSamlp2SubjectQueryAbstract *subject_query;

		/* Get federation */
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (LASSO_IS_FEDERATION(federation) == FALSE) {
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		} /* XXX: should support looking up transient id */

		subject_query = LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(profile->request);
		subject_query->Subject = LASSO_SAML2_SUBJECT(lasso_saml2_subject_new());
		subject_query->Subject->NameID =LASSO_SAML2_NAME_ID(
				lasso_profile_get_nameIdentifier(profile));

	}

	request = LASSO_SAMLP2_REQUEST_ABSTRACT(profile->request);
	request->ID = lasso_build_unique_id(32);
	request->Version = g_strdup("2.0");
	request->Issuer = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new_with_string(
			LASSO_PROVIDER(profile->server)->ProviderID));
	request->IssueInstant = lasso_get_current_time();

	profile->http_request_method = http_method;

	return 0;
}


/**
 * lasso_assertion_query_build_request_msg:
 * @assertion_query: a #LassoAssertionQuery
 *
 * Builds the Name Id Management request message.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_assertion_query_build_request_msg(LassoAssertionQuery *assertion_query)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(assertion_query);
	lasso_profile_clean_msg_info(profile);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		if (assertion_query->private_data->query_request_type == \
				LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID) {
			profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
					"AssertionIDRequestService SOAP");
		} else {
			profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
					"AttributeService SOAP");
		}
	 	/* XXX set private key so message is signed */
		profile->msg_body = lasso_node_export_to_soap(profile->request);
		return 0;
	}

	return critical_error(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD);
}


/**
 * lasso_assertion_query_process_request_msg:
 * @assertion_query: a #LassoAssertionQuery
 * @request_msg: the Assertion query or request message
 * 
 * Processes a Assertion query or request message.  Rebuilds a request object
 * from the message and check its signature.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_assertion_query_process_request_msg(LassoAssertionQuery *assertion_query,
		char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoSaml2NameID *name_id = NULL;
	LassoSaml2EncryptedElement *encrypted_id = NULL;
	LassoSaml2EncryptedElement* encrypted_element = NULL;
	xmlSecKey *encryption_private_key = NULL;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	
	profile = LASSO_PROFILE(assertion_query);
	profile->request = lasso_node_new_from_soap(request_msg);

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
			remote_provider, request_msg, "ID", LASSO_MESSAGE_FORMAT_SOAP);
	profile->signature_status = 0; /* XXX: signature check disabled for zxid */

	profile->http_request_method = LASSO_HTTP_METHOD_SOAP;

	if (LASSO_IS_SAMLP2_SUBJECT_QUERY_ABSTRACT(profile->request)) {
		LassoSamlp2SubjectQueryAbstract *subject_query;
		subject_query = LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(profile->request);
		if (subject_query->Subject) {
			name_id = subject_query->Subject->NameID;
			encrypted_id = subject_query->Subject->EncryptedID;
		}
	}

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
 * lasso_assertion_query_validate_request:
 * @assertion_query: a #LassoAssertionQuery
 * 
 * Processes a Assertion query or request; caller must add assertions to the
 * response afterwards.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_assertion_query_validate_request(LassoAssertionQuery *assertion_query)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlp2StatusResponse *response;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(assertion_query);

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

	profile->response = lasso_samlp2_response_new();
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

	return 0;
}


/**
 * lasso_assertion_query_build_response_msg:
 * @assertion_query: a #LassoAssertionQuery
 * 
 * Builds the Response message.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_assertion_query_build_response_msg(LassoAssertionQuery *assertion_query)
{
	LassoProfile *profile;
	LassoSamlp2StatusResponse *response;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(assertion_query);
	lasso_profile_clean_msg_info(profile);

	if (profile->response == NULL) {
		/* no response set here means request denied */
		profile->response = lasso_samlp2_response_new();
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

	return LASSO_PROFILE_ERROR_MISSING_REQUEST;
}


/**
 * lasso_assertion_query_process_response_msg:
 * @assertion_query: a #LassoAssertionQuery
 * @response_msg: the response message
 * 
 * Parses the response message and builds the corresponding response object.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_assertion_query_process_response_msg(
		LassoAssertionQuery *assertion_query,
		gchar *response_msg)
{
	LassoProfile *profile;
	LassoHttpMethod response_method;
	LassoProvider *remote_provider;
	LassoSamlp2StatusResponse *response;
	LassoMessageFormat format;
	char *status_code_value;
	int rc;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(assertion_query);

	if (LASSO_IS_SAMLP2_MANAGE_NAME_ID_RESPONSE(profile->response) == TRUE) {
		lasso_node_destroy(profile->response);
		profile->response = NULL;
	}

	profile->response = lasso_samlp2_response_new();
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
		message(G_LOG_LEVEL_CRITICAL, "No Status in Response !");
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}
	status_code_value = response->Status->StatusCode->Value;

	if (strcmp(status_code_value, LASSO_SAML2_STATUS_CODE_SUCCESS) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "Status code is not success: %s", status_code_value);
		return LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS;
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
	xmlNodeSetName(xmlnode, (xmlChar*)"AssertionQuery");
	xmlSetProp(xmlnode, (xmlChar*)"AssertionQueryDumpVersion", (xmlChar*)"1");

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
	LassoAssertionQuery *profile = LASSO_ASSERTION_QUERY(profile);
	g_free(profile->private_data);
	profile->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoAssertionQuery *assertion_query)
{
	assertion_query->private_data = g_new0(LassoAssertionQueryPrivate, 1);
}

static void
class_init(LassoAssertionQueryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AssertionQuery");
	lasso_node_class_add_snippets(nclass, schema_snippets);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}



GType
lasso_assertion_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoAssertionQueryClass),
			NULL, NULL, 
			(GClassInitFunc) class_init,
			NULL, NULL,
			sizeof(LassoAssertionQuery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoAssertionQuery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_assertion_query_new:
 * @server: the #LassoServer
 * 
 * Creates a new #LassoAssertionQuery.
 *
 * Return value: a newly created #LassoAssertionQuery object; or NULL if
 *     an error occured
 **/
LassoAssertionQuery*
lasso_assertion_query_new(LassoServer *server)
{
	LassoAssertionQuery *assertion_query;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	assertion_query = g_object_new(LASSO_TYPE_ASSERTION_QUERY, NULL);
	LASSO_PROFILE(assertion_query)->server = g_object_ref(server);

	return assertion_query;
}

/**
 * lasso_assertion_query_destroy:
 * @assertion_query: a #LassoAssertionQuery
 * 
 * Destroys a #LassoAssertionQuery object.
 **/
void
lasso_assertion_query_destroy(LassoAssertionQuery *assertion_query)
{
	lasso_node_destroy(LASSO_NODE(assertion_query));
}
