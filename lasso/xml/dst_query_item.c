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

#include <lasso/xml/dst_query_item.h>


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

/* FIXME : implement includeCommonAttributes attribute in snippets */
#define snippets() \
	LassoDstQueryItem *query_item = LASSO_DST_QUERY_ITEM(node); \
	struct XmlSnippet snippets[] = { \
                { "Select", SNIPPET_LIST_NODES, (void**)&(query_item->Select) }, \
                { "id", SNIPPET_ATTRIBUTE, (void**)&(query_item->id) }, \
                { "itemID", SNIPPET_ATTRIBUTE, (void**)&(query_item->itemID) }, \
                { "changedSince", SNIPPET_ATTRIBUTE, (void**)&(query_item->changedSince) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "QueryItem");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, NULL, NULL));

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
instance_init(LassoDstQueryItem *node)
{
	node->Select = NULL;

	node->id = NULL;
	node->includeCommonAttributes = FALSE;
	node->itemID = NULL;
	node->changedSince = NULL;
}

static void
class_init(LassoDstQueryItemClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_dst_query_item_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstQueryItemClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstQueryItem),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstQueryItem", &this_info, 0);
	}
	return this_type;
}

LassoDstQueryItem*
lasso_dst_query_item_new(const char *id,
			 const char *itemID,
			 const char *changedSince)
{
	LassoDstQueryItem *node;

	node = g_object_new(LASSO_TYPE_DST_QUERY_ITEM, NULL);

	node->id = g_strdup(id);
	node->itemID = g_strdup(itemID);
	node->changedSince = g_strdup(changedSince);

	return node;
}

