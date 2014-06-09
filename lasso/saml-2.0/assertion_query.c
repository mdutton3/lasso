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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "../id-ff/session.h"
#include "../xml/private.h"
#include "assertion_query.h"
#include "providerprivate.h"
#include "profileprivate.h"
#include "../id-ff/providerprivate.h"
#include "../id-ff/profileprivate.h"
#include "../id-ff/identityprivate.h"
#include "../id-ff/serverprivate.h"
#include "../xml/xml_enc.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/samlp2_assertion_id_request.h"
#include "../xml/saml-2.0/samlp2_authn_query.h"
#include "../xml/saml-2.0/samlp2_attribute_query.h"
#include "../xml/saml-2.0/samlp2_authz_decision_query.h"
#include "../xml/saml-2.0/samlp2_response.h"
#include "../xml/saml-2.0/samlp2_subject_query_abstract.h"
#include "../utils.h"


struct _LassoAssertionQueryPrivate
{
	LassoAssertionQueryRequestType query_request_type;
};

LassoMdProtocolType
_lasso_assertion_query_type_to_protocol_type(LassoAssertionQueryRequestType query_request_type) {

	LassoMdProtocolType types[4] = {
		LASSO_MD_PROTOCOL_TYPE_ASSERTION_ID_REQUEST,
		LASSO_MD_PROTOCOL_TYPE_AUTHN_QUERY,
		LASSO_MD_PROTOCOL_TYPE_ATTRIBUTE,
		LASSO_MD_PROTOCOL_TYPE_AUTHZ, };

	if (query_request_type < LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID ||
			query_request_type > LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION) {
		return -1;
	}

	return types[query_request_type - LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID];
}


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_assertion_query_init_request:
 * @assertion_query: a #LassoAssertionQuery
 * @remote_provider_id: (allow-none): the providerID of the remote provider.
 * @http_method: if set, then it get the protocol profile in metadata
 *     corresponding of this HTTP request method.
 * @query_request_type: the type of request.
 *
 * Initializes a new Assertion Query Request.
 * For the AssertionID request type, the remote_provider_id is mandatory, for all other kind of
 * request it is optional if we can find a provider supporting the associated role, i.e.
 * IDP; authentication, attribute and authorization authority.
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
	LassoNode *request;
	gint rc = 0;

	g_return_val_if_fail(http_method == LASSO_HTTP_METHOD_ANY ||
			http_method == LASSO_HTTP_METHOD_SOAP,
			LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(assertion_query);

	/* set the remote provider id */
	profile->remote_providerID = NULL;
	if (remote_provider_id) {
		profile->remote_providerID = g_strdup(remote_provider_id);
	} else {
		LassoProviderRole role = LASSO_PROVIDER_ROLE_NONE;
		switch (query_request_type) {
			case LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHN:
				role = LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY;
				break;
			case LASSO_ASSERTION_QUERY_REQUEST_TYPE_ATTRIBUTE:
				role = LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY;
				break;
			case LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION:
				role = LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY;
				break;
			/* other request types should not happen or should not go there */
			default:
				return critical_error(LASSO_PARAM_ERROR_INVALID_VALUE);
		}
		profile->remote_providerID =
			lasso_server_get_first_providerID_by_role(profile->server,
								role);
	}
	g_return_val_if_fail(profile->remote_providerID != NULL,
		LASSO_PARAM_ERROR_INVALID_VALUE);

	assertion_query->private_data->query_request_type = query_request_type;
	switch (query_request_type) {
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID:
			request = lasso_samlp2_assertion_id_request_new();
			break;
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHN:
			request = lasso_samlp2_authn_query_new();
			break;
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_ATTRIBUTE:
			request = lasso_samlp2_attribute_query_new();
			break;
		case LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION:
			request = lasso_samlp2_authz_decision_query_new();
			break;
		default:
			return critical_error(LASSO_PARAM_ERROR_INVALID_VALUE);
	}

        /* Setup usual request attributes */
	if (LASSO_IS_SAMLP2_SUBJECT_QUERY_ABSTRACT(request)) {
		LassoSamlp2SubjectQueryAbstract *sqa;

		sqa = (LassoSamlp2SubjectQueryAbstract*)request;
		sqa->Subject = (LassoSaml2Subject*)lasso_saml2_subject_new();
	}
	lasso_check_good_rc(lasso_saml20_profile_init_request(profile,
		profile->remote_providerID,
		TRUE,
		(LassoSamlp2RequestAbstract*)request,
		http_method,
		_lasso_assertion_query_type_to_protocol_type(query_request_type)));
cleanup:
	lasso_release_gobject(request);
	return rc;
}


/**
 * lasso_assertion_query_build_request_msg:
 * @assertion_query: a #LassoAssertionQuery
 *
 * Build an Assertion Query profile request message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_assertion_query_build_request_msg(LassoAssertionQuery *assertion_query)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	gint rc = 0;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(assertion_query);
	lasso_profile_clean_msg_info(profile);

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* fill and encrypt <Subject> if necessary */
	if (LASSO_IS_SAMLP2_SUBJECT_QUERY_ABSTRACT(profile->request)) do {
		LassoSaml2NameID *nameID = NULL;
		LassoSamlp2SubjectQueryAbstract *subject_query;

		subject_query = (LassoSamlp2SubjectQueryAbstract*)profile->request;
		if (! LASSO_IS_SAML2_SUBJECT(subject_query->Subject)) {
			lasso_assign_new_gobject(subject_query->Subject,
					lasso_saml2_subject_new());
		}
		/* verify that there is a NameID */
		if ( (! LASSO_IS_SAML2_NAME_ID(subject_query->Subject->NameID) &&
		      ! LASSO_IS_SAML2_ENCRYPTED_ELEMENT(subject_query->Subject->EncryptedID)))
		{
			/* if not try to get the local profile one */
			nameID = (LassoSaml2NameID*)profile->nameIdentifier;
			if (! LASSO_IS_SAML2_NAME_ID(nameID))
				nameID = (LassoSaml2NameID*)lasso_profile_get_nameIdentifier(profile);
			/* if none found, try to get the identity object or session object one */
			if (! LASSO_IS_SAML2_NAME_ID(nameID))
				return LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER;
			lasso_assign_gobject(subject_query->Subject->NameID, nameID);
		}
		lasso_check_good_rc(lasso_saml20_profile_setup_subject(profile,
					subject_query->Subject));
	} while(FALSE);

	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		LassoAssertionQueryRequestType type;
		const char *url;
		/* XXX: support only SOAP */
		static const gchar *servicepoints[LASSO_ASSERTION_QUERY_REQUEST_TYPE_LAST] = {
			NULL,
			NULL,
			"AuthnQueryService SOAP",
			"AttributeService SOAP",
			"AuthzService SOAP",
		};
		static const LassoProviderRole roles[LASSO_ASSERTION_QUERY_REQUEST_TYPE_LAST] = {
			LASSO_PROVIDER_ROLE_NONE,
			LASSO_PROVIDER_ROLE_NONE,
			LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY,
			LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY,
			LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY,
		};

		type = assertion_query->private_data->query_request_type;
		if (type == LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID) {
			return LASSO_ERROR_UNDEFINED;
		}
		if (type < LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID ||
		    type > LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION) {
			return LASSO_PARAM_ERROR_INVALID_VALUE;
		}
		url = lasso_provider_get_metadata_one_for_role(remote_provider, roles[type], servicepoints[type]);

		return lasso_saml20_profile_build_request_msg(&assertion_query->parent,
				NULL,
				LASSO_HTTP_METHOD_SOAP, url);
	}
cleanup:
	return rc;
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
	LassoProfile *profile = NULL;
	LassoSamlp2SubjectQueryAbstract *subject_query = NULL;
	LassoSaml2Subject *subject = NULL;
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(assertion_query);
	lasso_check_good_rc(lasso_saml20_profile_process_soap_request(profile, request_msg));
	lasso_extract_node_or_fail(subject_query, profile->request, SAMLP2_SUBJECT_QUERY_ABSTRACT,
			LASSO_PROFILE_ERROR_INVALID_MSG);
	lasso_extract_node_or_fail(subject, subject_query->Subject, SAML2_SUBJECT,
			LASSO_PROFILE_ERROR_MISSING_SUBJECT);
	lasso_check_good_rc(lasso_saml20_profile_process_name_identifier_decryption(profile, &subject->NameID, &subject->EncryptedID));

cleanup:
	return rc;
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
	LassoSamlp2StatusResponse *response;
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(assertion_query);

	response = (LassoSamlp2StatusResponse*) lasso_samlp2_response_new();
	lasso_check_good_rc(lasso_saml20_profile_validate_request(profile,
				FALSE,
				response,
				&remote_provider));

cleanup:
	lasso_release_gobject(response);
	return rc;
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
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_PARAM_ERROR_INVALID_VALUE);
	profile = LASSO_PROFILE(assertion_query);
	lasso_profile_clean_msg_info(profile);

	if (profile->response == NULL) {
		/* no response set here means request denied */
		response = (LassoSamlp2StatusResponse*) lasso_samlp2_response_new();

		lasso_check_good_rc(lasso_saml20_profile_init_response(
					profile,
					response,
					LASSO_SAML2_STATUS_CODE_RESPONDER,
					LASSO_SAML2_STATUS_CODE_REQUEST_DENIED));
		return 0;
	}

	/* build logout response message */
	rc = lasso_saml20_profile_build_response_msg(profile,
			NULL,
			profile->http_request_method,
			NULL);
cleanup:
	return rc;
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
	LassoProfile *profile = NULL;
	LassoSamlp2StatusResponse *response = NULL;
	int rc = 0;

	lasso_bad_param(ASSERTION_QUERY, assertion_query);
	profile = &assertion_query->parent;

	lasso_check_good_rc(lasso_saml20_profile_process_soap_response(profile,
				response_msg));

cleanup:
	lasso_release_gobject(response);
	return rc;
}

static LassoSaml2Attribute*
lasso_assertion_query_lookup_attribute(LassoAssertionQuery *assertion_query, char *format, char *name)
{
	LassoSaml2Attribute *result = NULL;
	LassoSamlp2AttributeQuery *query = NULL;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query) || ! format || ! name,
			NULL);

	query = (LassoSamlp2AttributeQuery*) assertion_query->parent.request;
	g_return_val_if_fail(LASSO_IS_SAMLP2_ATTRIBUTE_QUERY(query), NULL);

	lasso_foreach_full_begin(LassoSaml2Attribute*, attribute, it, query->Attribute)
	{
		if (LASSO_IS_SAML2_ATTRIBUTE(attribute) &&
				lasso_strisequal(attribute->NameFormat,format) &&
				lasso_strisequal(attribute->Name,name))
		{
			result = attribute;
			break;
		}
	}
	lasso_foreach_full_end()

	return result;
}

/**
 * lasso_assertion_query_add_attribute_request:
 * @assertion_query: a #LassoAssertionQuery object
 * @attribute_format: the attribute designator format
 * @attribute_name: the attribute designator name
 *
 * Append a new attribute designator to the current attribute request.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_assertion_query_add_attribute_request(LassoAssertionQuery *assertion_query,
		char *format, char *name)
{
	int rc = 0;
	LassoSaml2Attribute *attribute = NULL;
	LassoSamlp2AttributeQuery *query = NULL;

	lasso_bad_param(ASSERTION_QUERY, assertion_query);
	lasso_null_param(format);
	lasso_null_param(name);
	query = (LassoSamlp2AttributeQuery*) assertion_query->parent.request;
	g_return_val_if_fail(LASSO_IS_SAMLP2_ATTRIBUTE_QUERY(query),
			LASSO_ASSERTION_QUERY_ERROR_NOT_AN_ATTRIBUTE_QUERY);

	/* Check unicity */
	attribute = lasso_assertion_query_lookup_attribute(assertion_query, format, name);
	if (attribute != NULL) {
		return LASSO_ASSERTION_QUERY_ERROR_ATTRIBUTE_REQUEST_ALREADY_EXIST;
	}
	/* Do the work */
	attribute = (LassoSaml2Attribute*)lasso_saml2_attribute_new();
	lasso_assign_string(attribute->NameFormat, format);
	lasso_assign_string(attribute->Name, name);
	lasso_list_add_new_gobject(query->Attribute, attribute);

	return rc;
}

/**
 * lasso_assertion_query_get_request_type:
 * @assertion_query: a #LassoAssertionQuery object
 *
 * Return the type of the last processed request.
 *
 * Return value: a #LassoAssertionQueryRequestType value
 */
LassoAssertionQueryRequestType
lasso_assertion_query_get_request_type(LassoAssertionQuery *assertion_query)
{
	LassoNode *request;
	GType type;

	g_return_val_if_fail(LASSO_IS_ASSERTION_QUERY(assertion_query),
			LASSO_ASSERTION_QUERY_REQUEST_TYPE_UNSET);

	request = assertion_query->parent.request;
	if (! G_IS_OBJECT(request))
		return LASSO_ASSERTION_QUERY_REQUEST_TYPE_UNSET;
	type = G_OBJECT_TYPE(request);
	if (type == LASSO_TYPE_SAMLP2_ASSERTION_ID_REQUEST)
		return LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID;
	if (type == LASSO_TYPE_SAMLP2_AUTHN_QUERY)
		return LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHN;
	if (type == LASSO_TYPE_SAMLP2_ATTRIBUTE_QUERY)
		return LASSO_ASSERTION_QUERY_REQUEST_TYPE_ATTRIBUTE;
	if (type == LASSO_TYPE_SAMLP2_AUTHZ_DECISION_QUERY)
		return LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION;
	return LASSO_ASSERTION_QUERY_REQUEST_TYPE_UNSET;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
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
finalize(GObject *object)
{
	LassoAssertionQuery *profile = LASSO_ASSERTION_QUERY(object);
	lasso_release(profile->private_data);
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
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

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
			NULL
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
	LASSO_PROFILE(assertion_query)->server = lasso_ref(server);
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
	lasso_release_gobject(assertion_query);
}
