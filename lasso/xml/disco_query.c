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

#include <lasso/xml/disco_query.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-v1.0.xsd):
 * 
 * <xs:group name="ResourceIDGroup">
 *   <xs:sequence>
 *      <xs:choice minOccurs="0" maxOccurs="1">
 *        <xs:element ref="ResourceID"/>
 *        <xs:element ref="EncryptedResourceID"/>
 *      </xs:choice>
 *   </xs:sequence>
 * </xs:group>
 * 
 * <xs:element name="Query" type="QueryType"/>
 * <xs:complexType name="QueryType">
 *   <xs:sequence>
 *      <xs:group ref="ResourceIDGroup"/>
 *      <xs:element name="RequestedServiceType" minOccurs="0" maxOccurs="unbounded">
 *        <xs:complexType>
 *           <xs:sequence>
 *             <xs:element ref="ServiceType"/>
 *             <xs:element ref="Options" minOccurs="0"/>
 *           </xs:sequence>
 *        </xs:complexType>
 *      </xs:element>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs: ID" use="optional"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDiscoQuery *query = LASSO_DISCO_QUERY(node); \
	struct XmlSnippetObsolete snippets[] = { \
		{ "ResourceID", SNIPPET_CONTENT, (void**)&query->ResourceID }, \
		{ "EncryptedResourceID", SNIPPET_CONTENT, (void**)&query->EncryptedResourceID }, \
		{ "RequestedServiceType", SNIPPET_LIST_NODES, \
			(void**)&query->RequestedServiceType }, \
		{ "id", SNIPPET_ATTRIBUTE, (void**)&query->id }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "Query");
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
instance_init(LassoDiscoQuery *node)
{
	node->ResourceID = NULL;
	node->EncryptedResourceID = NULL;
	node->RequestedServiceType = NULL;
	node->id = NULL;
}

static void
class_init(LassoDiscoQueryClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_disco_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoQueryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoQuery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoQuery", &this_info, 0);
	}
	return this_type;
}

LassoDiscoQuery*
lasso_disco_query_new(const char *resourceID, gboolean is_encrypted)
{
	LassoDiscoQuery *node;

	g_return_val_if_fail (resourceID != NULL, NULL);

	node = g_object_new(LASSO_TYPE_DISCO_QUERY, NULL);

	if (is_encrypted == TRUE) {
		node->EncryptedResourceID = g_strdup(resourceID);
	}
	else {
		node->ResourceID = g_strdup(resourceID);
	}

	return node;
}
