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

#include <lasso/xml/lib_status_response.h>
#include <libxml/uri.h>

/*
 * Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):
 * 
 * <xs:complexType name="StatusResponseType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:ResponseAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="samlp:Status"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
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

#define snippets() \
	LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(node); \
	struct XmlSnippet snippets[] = { \
		{ "ProviderID", SNIPPET_CONTENT, (void**)&(response->ProviderID) }, \
		{ "Status", SNIPPET_NODE, (void**)&(response->Status) }, \
		{ "RelayState", SNIPPET_CONTENT, (void**)&(response->RelayState) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "StatusResponse");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));
	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	init_xml_with_snippets(xmlnode, snippets);
	return 0;
}

static gchar*
build_query(LassoNode *node)
{
	char *str, *t;
	GString *s;
	LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(node);

	str = parent_class->build_query(node);
	s = g_string_new(str);
	g_free(str);

	/* XXX Extension */
	if (response->ProviderID) {
		t = xmlURIEscapeStr(response->ProviderID, NULL);
		g_string_append_printf(s, "&ProviderID=%s", t);
		xmlFree(t);
	}
	if (response->RelayState) {
		t = xmlURIEscapeStr(response->RelayState, NULL);
		g_string_append_printf(s, "&RelayState=%s", t);
		xmlFree(t);
	}
	if (response->Status) {
		t = xmlURIEscapeStr(response->Status->StatusCode->Value, NULL);
		g_string_append_printf(s, "&Value=%s", t);
		xmlFree(t);
	}

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(node);
	int i;
	char *t;

	for (i=0; (t=query_fields[i]); i++) {
		if (g_str_has_prefix(t, "ProviderID=")) {
			response->ProviderID = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "RelayState=")) {
			response->RelayState = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "Value=")) {
			response->Status = lasso_samlp_status_new();
			response->Status->StatusCode = lasso_samlp_status_code_new();
			response->Status->StatusCode->Value = g_strdup(t+6);
			continue;
		}
	}

	if (response->ProviderID == NULL || response->Status == NULL)
		return FALSE;
	
	return parent_class->init_from_query(node, query_fields);
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibStatusResponse *node)
{
	node->ProviderID = NULL;
	node->Status = NULL;
	node->RelayState = NULL;
}

static void
class_init(LassoLibStatusResponseClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
}

GType
lasso_lib_status_response_get_type()
{
	static GType status_response_type = 0;

	if (!status_response_type) {
		static const GTypeInfo status_response_info = {
			sizeof (LassoLibStatusResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibStatusResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		status_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
				"LassoLibStatusResponse", &status_response_info, 0);
	}
	return status_response_type;
}

LassoNode* lasso_lib_status_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_STATUS_RESPONSE, NULL);
}

