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

#include <libxml/uri.h>
#include <lasso/xml/lib_logout_request.h>

/*
 * Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):
 * 
 * <xs:element name="LogoutRequest" type="LogoutRequestType"/>
 * <xs:complexType name="LogoutRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="saml:NameIdentifier"/>
 *         <xs:element name="SessionIndex" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *       <xs:attribute name="NotOnOrAfter" type="xs:dateTime" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * 
 * <xs:element name="ProviderID" type="md:entityIDType"/>
 * <xs:element name="RelayState" type="xs:string"/>
 * 
 * From liberty-metadata-v1.0.xsd:
 * <xs:simpleType name="entityIDType">
 *   <xs:restriction base="xs:anyURI">
 *     <xs:maxLength value="1024" id="maxlengthid"/>
 *   </xs:restriction>
 * </xs:simpleType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoLibLogoutRequest, Extension) },
	{ "ProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibLogoutRequest, ProviderID) },
	{ "NameIdentifier", SNIPPET_NODE, G_STRUCT_OFFSET(LassoLibLogoutRequest, NameIdentifier) },
	{ "SessionIndex", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibLogoutRequest, SessionIndex) },
	{ "RelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibLogoutRequest, RelayState) },
	{ "consent", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoLibLogoutRequest, consent) },
	{ "NotOnOrAfter", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibLogoutRequest, NotOnOrAfter) },
	{ NULL, 0, 0}
};

static struct QuerySnippet query_snippets[] = {
	{ "RequestID", NULL },
	{ "MajorVersion", NULL },
	{ "MinorVersion", NULL },
	{ "IssueInstant", NULL },
	{ "ProviderID", NULL },
	{ "NameIdentifier/NameQualifier", "NameQualifier" },
	{ "NameIdentifier/Format", "NameFormat" },
	{ "NameIdentifier/content", "NameIdentifier" },
	{ "SessionIndex", NULL },
	{ "RelayState", NULL },
	{ "consent", NULL },
	{ NULL, NULL }
};


static LassoNodeClass *parent_class = NULL;

static gchar*
build_query(LassoNode *node)
{
	return lasso_node_build_query_from_snippets(node);
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibLogoutRequest *request = LASSO_LIB_LOGOUT_REQUEST(node);

	request->NameIdentifier = lasso_saml_name_identifier_new();

	lasso_node_init_from_query_fields(node, query_fields);
	
	if (request->ProviderID == NULL ||
			request->NameIdentifier->content == NULL ||
			request->NameIdentifier->Format == NULL ||
			request->NameIdentifier->NameQualifier == NULL) {
		lasso_node_destroy(LASSO_NODE(request->NameIdentifier));
		request->NameIdentifier = NULL;
		return FALSE;
	}
	
	return TRUE;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibLogoutRequest *node)
{
	node->ProviderID = NULL;
	node->NameIdentifier = NULL;
	node->SessionIndex = NULL;
	node->RelayState = NULL;
	node->consent = NULL;
}

static void
class_init(LassoLibLogoutRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "LogoutRequest");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	lasso_node_class_add_query_snippets(nclass, query_snippets);
}

GType
lasso_lib_logout_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibLogoutRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibLogoutRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibLogoutRequest", &this_info, 0);
	}
	return this_type;
}

LassoSamlpRequestAbstract*
lasso_lib_logout_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST, NULL);
}

LassoSamlpRequestAbstract*
lasso_lib_logout_request_new_full(char *providerID, LassoSamlNameIdentifier *nameIdentifier,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();
	request->sign_type = sign_type;
	request->sign_method = sign_method;
	LASSO_LIB_LOGOUT_REQUEST(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_LOGOUT_REQUEST(request)->NameIdentifier = g_object_ref(nameIdentifier);

	return request;
}
