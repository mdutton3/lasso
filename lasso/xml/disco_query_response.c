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

#include <lasso/xml/disco_query_response.h>

/*
 * Schema fragment:
 *
 * <xs:element name="QueryResponse" type="QueryResponseType"/>
 * <xs:complexType name="QueryResponseType">
 *   <xs:sequence>
 *     <xs:element ref="Status"/>
 *     <xs:element ref="ResourceOffering" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="Credentials" minOccurs="0">
 *       <xs:complexType>
 *         <xs:sequence>
 *           <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *       </xs:complexType>
 *     </xs:element>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

#define snippets() \
	LassoDiscoQueryResponse *query_response = LASSO_DISCO_QUERY_RESPONSE(node); \
	struct XmlSnippet snippets[] = { \
		{ "Status", SNIPPET_NODE, (void**)&query_response->Status }, \
		{ "ResourceOffering", SNIPPET_LIST_NODES, \
			(void**)&query_response->ResourceOffering }, \
		{ "Credentials", SNIPPET_NODE, (void**)&query_response->Credentials }, \
		{ "id", SNIPPET_ATTRIBUTE, (void**)&query_response->id }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "QueryResponse");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));

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

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoQueryResponse *node)
{
	node->Status = NULL;
	node->ResourceOffering = NULL;
	node->Credentials = NULL;
	
	node->id = NULL;
}

static void
class_init(LassoDiscoQueryResponseClass *class)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(class);

	parent_class = g_type_class_peek_parent(class);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_disco_query_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoQueryResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoQueryResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoQueryResponse", &this_info, 0);
	}
	return this_type;
}

LassoDiscoQueryResponse*
lasso_disco_query_response_new(LassoUtilityStatus *Status)
{
	LassoDiscoQueryResponse *node;

	node = g_object_new(LASSO_TYPE_DISCO_QUERY_RESPONSE, NULL);

	node->Status = Status;

	return node;
}
