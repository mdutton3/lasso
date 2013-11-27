/* $Id: subsref_query_item.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "subsref_query_item.h"
#include "idwsf2_strings.h"

/**
 * SECTION:subsref_query_item
 * @short_description: &lt;subsref:QueryItem&gt;
 *
 * <figure><title>Schema fragment for subsref:QueryItem</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="QueryItemType">
 *   <xs:complexContent>
 *     <xs:extension base="subsref:ResultQueryType">
 *       <xs:attributeGroup ref="dst:PaginationAttributeGroup"/>
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
	{ "count", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQueryItem, count), NULL, NULL, NULL},
	{ "offset", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQueryItem, offset), NULL, NULL, NULL},
	{ "setID", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQueryItem, setID), NULL, NULL, NULL},
	{ "setReq", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQueryItem, setReq), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2SubsRefQueryItem *node)
{
	node->count = -1;
	node->offset = -1;
}

static void
class_init(LassoIdWsf2SubsRefQueryItemClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "QueryItem");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SUBSREF_HREF, LASSO_IDWSF2_SUBSREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_subsref_query_item_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SubsRefQueryItemClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SubsRefQueryItem),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_SUBSREF_RESULT_QUERY,
				"LassoIdWsf2SubsRefQueryItem", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_subsref_query_item_new:
 *
 * Creates a new #LassoIdWsf2SubsRefQueryItem object.
 *
 * Return value: a newly created #LassoIdWsf2SubsRefQueryItem object
 **/
LassoIdWsf2SubsRefQueryItem*
lasso_idwsf2_subsref_query_item_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SUBSREF_QUERY_ITEM, NULL);
}
