/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/xml/disco_insert_entry.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-v1.0.xsd):
 * 
 * <xs:complexType name="InsertEntryType">
 *   <xs:sequence>
 *     <xs:element ref="ResourceOffering"/>
 *     <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDiscoInsertEntry *entry = LASSO_DISCO_INSERT_ENTRY(node); \
	struct XmlSnippetObsolete snippets[] = { \
		{ "ResourceOffering", SNIPPET_NODE, (void**)&(entry->ResourceOffering) }, \
		{ "any", SNIPPET_LIST_NODES, (void**)&(entry->any) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "InsertEntry");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));
	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode)) {
		return -1;
	}

	init_xml_with_snippets(xmlnode, snippets);
	
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoInsertEntry *node)
{
	node->ResourceOffering = NULL;
	node->any = NULL;
}

static void
class_init(LassoDiscoInsertEntryClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_disco_insert_entry_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoInsertEntryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoInsertEntry),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoInsertEntry", &this_info, 0);
	}
	return this_type;
}

LassoDiscoInsertEntry*
lasso_disco_insert_entry_new()
{
	return g_object_new(LASSO_TYPE_DISCO_INSERT_ENTRY, NULL);
}
