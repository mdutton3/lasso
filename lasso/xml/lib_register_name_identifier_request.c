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
#include <lasso/xml/lib_register_name_identifier_request.h>

/*
 * Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):
 * 
 * <xs:element name="RegisterNameIdentifierRequest" type="RegisterNameIdentifierRequestType"/>
 * <xs:complexType name="RegisterNameIdentifierRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="IDPProvidedNameIdentifier"/>
 *         <xs:element ref="SPProvidedNameIdentifier" minOccurs="0"/>
 *         <xs:element ref="OldProvidedNameIdentifier"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * <xs:element name="IDPProvidedNameIdentifier" type="saml:NameIdentifierType"/>
 * <xs:element name="SPProvidedNameIdentifier" type="saml:NameIdentifierType"/>
 * <xs:element name="OldProvidedNameIdentifier" type="saml:NameIdentifierType"/>
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
	/* TODO: <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, ProviderID) },
	{ "IDPProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, IDPProvidedNameIdentifier)},
	{ "SPProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, SPProvidedNameIdentifier) },
	{ "OldProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, OldProvidedNameIdentifier)},
	{ "RelayState", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, RelayState) },
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static gchar*
build_query(LassoNode *node)
{
	char *str, *t;
	GString *s;
	LassoLibRegisterNameIdentifierRequest *request;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	str = parent_class->build_query(node);
	s = g_string_new(str);
	g_free(str);

	if (request->ProviderID) {
		t = xmlURIEscapeStr(request->ProviderID, NULL);
		g_string_append_printf(s, "&ProviderID=%s", t);
		xmlFree(t);
	}
	if (request->IDPProvidedNameIdentifier) {
		t = lasso_saml_name_identifier_build_query(
				request->IDPProvidedNameIdentifier, "IDP", "IDPProvided");
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->SPProvidedNameIdentifier) {
		t = lasso_saml_name_identifier_build_query(
				request->SPProvidedNameIdentifier, "SP", "SPProvided");
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->OldProvidedNameIdentifier) {
		t = lasso_saml_name_identifier_build_query(
				request->OldProvidedNameIdentifier, "Old", "OldProvided");
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->RelayState)
		g_string_append_printf(s, "&RelayState=%s", request->RelayState);

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibRegisterNameIdentifierRequest *request;
	int i;
	char *t;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	request->IDPProvidedNameIdentifier = lasso_saml_name_identifier_new();
	request->SPProvidedNameIdentifier = lasso_saml_name_identifier_new();
	request->OldProvidedNameIdentifier = lasso_saml_name_identifier_new();
	
	for (i=0; (t=query_fields[i]); i++) {
		if (g_str_has_prefix(t, "ProviderID=")) {
			request->ProviderID = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "RelayState=")) {
			request->RelayState = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "IDPProvidedNameIdentifier=")) {
			request->IDPProvidedNameIdentifier->content = g_strdup(t+26);
			continue;
		}
		if (g_str_has_prefix(t, "IDPNameFormat=")) {
			request->IDPProvidedNameIdentifier->Format = g_strdup(t+14);
			continue;
		}
		if (g_str_has_prefix(t, "IDPNameQualifier=")) {
			request->IDPProvidedNameIdentifier->NameQualifier = g_strdup(t+17);
			continue;
		}
		if (g_str_has_prefix(t, "SPProvidedNameIdentifier=")) {
			request->SPProvidedNameIdentifier->content = g_strdup(t+25);
			continue;
		}
		if (g_str_has_prefix(t, "SPNameFormat=")) {
			request->SPProvidedNameIdentifier->Format = g_strdup(t+13);
			continue;
		}
		if (g_str_has_prefix(t, "SPNameQualifier=")) {
			request->SPProvidedNameIdentifier->NameQualifier = g_strdup(t+16);
			continue;
		}
		if (g_str_has_prefix(t, "OldProvidedNameIdentifier=")) {
			request->OldProvidedNameIdentifier->content = g_strdup(t+26);
			continue;
		}
		if (g_str_has_prefix(t, "OldNameFormat=")) {
			request->OldProvidedNameIdentifier->Format = g_strdup(t+14);
			continue;
		}
		if (g_str_has_prefix(t, "OldNameQualifier=")) {
			request->OldProvidedNameIdentifier->NameQualifier = g_strdup(t+17);
			continue;
		}
	}

	if (request->IDPProvidedNameIdentifier->content == NULL) {
		g_object_unref(request->IDPProvidedNameIdentifier);
		request->IDPProvidedNameIdentifier = NULL;
	}
	if (request->SPProvidedNameIdentifier->content == NULL) {
		g_object_unref(request->SPProvidedNameIdentifier);
		request->SPProvidedNameIdentifier = NULL;
	}
	if (request->OldProvidedNameIdentifier->content == NULL) {
		g_object_unref(request->OldProvidedNameIdentifier);
		request->OldProvidedNameIdentifier = NULL;
	}

	if (request->ProviderID == NULL ||
			request->OldProvidedNameIdentifier == NULL ||
			request->IDPProvidedNameIdentifier == NULL) {
		return FALSE;
	}
	
	return parent_class->init_from_query(node, query_fields);
}




/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibRegisterNameIdentifierRequest *node)
{
	node->ProviderID = NULL;
	node->IDPProvidedNameIdentifier = NULL;
	node->SPProvidedNameIdentifier = NULL;
	node->OldProvidedNameIdentifier = NULL;
	node->RelayState = NULL;
}

static void
class_init(LassoLibRegisterNameIdentifierRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RegisterNameIdentifierRequest");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_register_name_identifier_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibRegisterNameIdentifierRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibRegisterNameIdentifierRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibRegisterNameIdentifierRequest", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_register_name_identifier_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, NULL);
}

LassoNode*
lasso_lib_register_name_identifier_request_new_full(const char *providerID,
		LassoSamlNameIdentifier *idpNameIdentifier,
		LassoSamlNameIdentifier *spNameIdentifier,
		LassoSamlNameIdentifier *oldNameIdentifier,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoLibRegisterNameIdentifierRequest *request;
	LassoSamlpRequestAbstract *request_base;

	request = g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, NULL);
	request_base = LASSO_SAMLP_REQUEST_ABSTRACT(request);

	request_base->RequestID = lasso_build_unique_id(32);
	request_base->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request_base->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request_base->IssueInstant = lasso_get_current_time();
	request_base->sign_type = sign_type;
	request_base->sign_method = sign_method;

	request->ProviderID = g_strdup(providerID);
	request->IDPProvidedNameIdentifier = idpNameIdentifier;
	request->SPProvidedNameIdentifier = spNameIdentifier;
	request->OldProvidedNameIdentifier = oldNameIdentifier;


	return LASSO_NODE(request);
}


