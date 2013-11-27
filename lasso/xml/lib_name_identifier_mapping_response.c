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

#include "private.h"
#include "lib_name_identifier_mapping_response.h"

/**
 * SECTION:lib_name_identifier_mapping_response
 * @short_description: &lt;lib:NameIdentifierMappingResponse&gt;
 *
 * <figure><title>Schema fragment for lib:NameIdentifierMappingResponse</title>
 * <programlisting><![CDATA[
 * <xs:element name="NameIdentifierMappingResponse" type="NameIdentifierMappingResponseType"/>
 * <xs:complexType name="NameIdentifierMappingResponseType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:ResponseAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="samlp:Status"/>
 *         <xs:element ref="saml:NameIdentifier" minOccurs="0"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingResponse, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingResponse, ProviderID), NULL, NULL, NULL},
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingResponse, Status), NULL,
		LASSO_SAML_PROTOCOL_PREFIX, LASSO_SAML_PROTOCOL_HREF},
	{ "NameIdentifier", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingResponse, NameIdentifier), NULL,
		LASSO_SAML_ASSERTION_PREFIX, LASSO_SAML_ASSERTION_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibNameIdentifierMappingResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "NameIdentifierMappingResponse");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_name_identifier_mapping_response_get_type()
{
	static GType name_identifier_mapping_response_type = 0;

	if (!name_identifier_mapping_response_type) {
		static const GTypeInfo name_identifier_mapping_response_info = {
			sizeof (LassoLibNameIdentifierMappingResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibNameIdentifierMappingResponse),
			0,
			NULL,
			NULL
		};

		name_identifier_mapping_response_type = g_type_register_static
			(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
			 "LassoLibNameIdentifierMappingResponse",
			 &name_identifier_mapping_response_info, 0);
	}
	return name_identifier_mapping_response_type;
}

/**
 * lasso_lib_name_identifier_mapping_response_new:
 *
 * Creates a new #LassoLibNameIdentifierMappingResponse object.
 *
 * Return value: a newly created #LassoLibNameIdentifierMappingResponse object
 **/
LassoNode*
lasso_lib_name_identifier_mapping_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL);
}


/**
 * lasso_lib_name_identifier_mapping_response_new_full:
 * @providerID: the providerID of the responder
 * @statusCodeValue: a response status code
 * @request: the request which is asnwered by this response
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibNameIdentifierMappingResponse object and initializes
 * it with the parameters.
 *
 * Return value: a newly created #LassoLibNameIdentifierMappingResponse object
 **/
LassoNode*
lasso_lib_name_identifier_mapping_response_new_full(char *providerID, const char *statusCodeValue,
		LassoLibNameIdentifierMappingRequest *request,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
{
	LassoLibNameIdentifierMappingResponse *response;

	response = g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL);
	lasso_samlp_response_abstract_fill(
			LASSO_SAMLP_RESPONSE_ABSTRACT(response),
			LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID,
			request->ProviderID);
	LASSO_SAMLP_RESPONSE_ABSTRACT(response)->sign_type = sign_type;
	LASSO_SAMLP_RESPONSE_ABSTRACT(response)->sign_method = sign_method;

	response->ProviderID = g_strdup(providerID);
	response->Status = lasso_samlp_status_new();
	response->Status->StatusCode = lasso_samlp_status_code_new();
	response->Status->StatusCode->Value = g_strdup(statusCodeValue);

	return LASSO_NODE(response);
}
