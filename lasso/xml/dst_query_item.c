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

/*
 * Schema fragment (liberty-idwsf-dst-v1.0.xsd):
 * <xs:element name="QueryItem" maxOccurs="unbounded">
 *    <xs:complexType>
 *        <xs:sequence>
 *            <xs:element name="Select" type="SelectType"/>
 *        </xs:sequence>
 *        <xs:attribute name="id" type="xs:ID"/>
 *        <xs:attribute name="includeCommonAttributes" type="xs:boolean" default="0"/>
 *        <xs:attribute name="itemID" type="IDType"/>
 *        <xs:attribute name="changedSince" type="xs:dateTime"/>
 *    </xs:complexType>
 * </xs:element>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Select", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDstQueryItem, Select) },
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQueryItem, id) },
	{ "includeCommonAttributes", SNIPPET_ATTRIBUTE_BOOL, \
	  G_STRUCT_OFFSET(LassoDstQueryItem, itemID) },
	{ "itemID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQueryItem, itemID) },
	{ "changedSince", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQueryItem, changedSince) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


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
	nodeClass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nodeClass, "QueryItem");
	lasso_node_class_add_snippets(nodeClass, schema_snippets);
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
lasso_dst_query_item_new(const char *Select)
{
	LassoDstQueryItem *node;

	node = g_object_new(LASSO_TYPE_DST_QUERY_ITEM, NULL);

	node->Select = g_strdup(Select);
	node->includeCommonAttributes = FALSE;

	return node;
}

