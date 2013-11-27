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
#include "lib_name_identifier_mapping_request.h"

/**
 * SECTION:lib_name_identifier_mapping_request
 * @short_description: &lt;lib:NameIdentifierMappingRequest&gt;
 *
 * <figure><title>Schema fragment for lib:NameIdentifierMappingRequest</title>
 * <programlisting><![CDATA[
 * <xs:element name="NameIdentifierMappingRequest" type="NameIdentifierMappingRequestType"/>
 * <xs:complexType name="NameIdentifierMappingRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="saml:NameIdentifier"/>
 *         <xs:element name="TargetNamespace" type="md:entityIDType"/>
 *       </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 *
 * <xs:element name="ProviderID" type="md:entityIDType"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingRequest, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingRequest, ProviderID), NULL, NULL, NULL},
	{ "NameIdentifier", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingRequest, NameIdentifier), NULL,
		LASSO_SAML_ASSERTION_PREFIX, LASSO_SAML_ASSERTION_HREF},
	{ "TargetNamespace", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingRequest, TargetNamespace), NULL, NULL, NULL},
	{ "consent", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibNameIdentifierMappingRequest, consent), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibNameIdentifierMappingRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "NameIdentifierMappingRequest");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_name_identifier_mapping_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibNameIdentifierMappingRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibNameIdentifierMappingRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibNameIdentifierMappingRequest", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_lib_name_identifier_mapping_request_new:
 *
 * Creates a new #LassoLibNameIdentifierMappingRequest object.
 *
 * Return value: a newly created #LassoLibNameIdentifierMappingRequest object
 **/
LassoNode*
lasso_lib_name_identifier_mapping_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, NULL);
}


/**
 * lasso_lib_name_identifier_mapping_request_new_full:
 * @providerID: the provider ID requesting the name identifier mapping
 * @nameIdentifier: a #LassoSamlNameIdentifier object
 * @targetNamespace: an URI for the target namespace
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibNameIdentifierMappingRequest object and initializes it with the
 * parameters. It also setups the signature on the request object, you must preceise the signing key
 * later.
 *
 * Return value: a newly created #LassoLibNameIdentifierMappingRequest object
 **/
LassoNode*
lasso_lib_name_identifier_mapping_request_new_full(char *providerID,
		LassoSamlNameIdentifier *nameIdentifier, const char *targetNamespace,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();
	request->sign_type = sign_type;
	request->sign_method = sign_method;

	/* ProviderID */
	LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request)->NameIdentifier =
		g_object_ref(nameIdentifier);

	LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request)->TargetNamespace =
		g_strdup(targetNamespace);

	/* XXX: consent ?  */

	return LASSO_NODE(request);
}
