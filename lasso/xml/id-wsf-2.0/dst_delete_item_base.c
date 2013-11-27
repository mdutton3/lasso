/* $Id: dst_delete_item_base.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "dst_delete_item_base.h"
#include "idwsf2_strings.h"

/**
 * SECTION:dst_delete_item_base
 * @short_description: &lt;dst:DeleteItemBase&gt;
 *
 * <figure><title>Schema fragment for dst:DeleteItemBase</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="DeleteItemBaseType">
 *   <xs:attributeGroup ref="dst:selectQualif"/>
 *   <xs:attribute name="notChangedSince" use="optional" type="xs:dateTime"/>
 *   <xs:attribute name="id" use="optional" type="xs:ID"/>
 *   <xs:attribute ref="lu:itemID" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "notChangedSince", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstDeleteItemBase, notChangedSince), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstDeleteItemBase, id), NULL, NULL, NULL},
	{ "itemID", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstDeleteItemBase, itemID), NULL, NULL, NULL},
	{ "objectType", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2DstDeleteItemBase, objectType), NULL, NULL, NULL},
	{ "predefined", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2DstDeleteItemBase, predefined), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DstDeleteItemBaseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "DeleteItemBase");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DST_HREF, LASSO_IDWSF2_DST_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_dst_delete_item_base_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DstDeleteItemBaseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DstDeleteItemBase),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DstDeleteItemBase", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_dst_delete_item_base_new:
 *
 * Creates a new #LassoIdWsf2DstDeleteItemBase object.
 *
 * Return value: a newly created #LassoIdWsf2DstDeleteItemBase object
 **/
LassoIdWsf2DstDeleteItemBase*
lasso_idwsf2_dst_delete_item_base_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DST_DELETE_ITEM_BASE, NULL);
}
