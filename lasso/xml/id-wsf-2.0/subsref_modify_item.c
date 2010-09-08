/* $Id: subsref_modify_item.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../private.h"
#include "subsref_modify_item.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:subsref_modify_item
 * @short_description: &lt;subsref:ModifyItem&gt;
 *
 * <figure><title>Schema fragment for subsref:ModifyItem</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ModifyItemType">
 *   <xs:sequence>
 *     <xs:element ref="subsref:Select" minOccurs="0" maxOccurs="1"/>
 *     <xs:element ref="subsref:NewData" minOccurs="0" maxOccurs="1"/>
 *   </xs:sequence>
 *   <xs:attributeGroup ref="dst:ModifyItemAttributeGroup"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Select", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefModifyItem, Select), NULL, NULL, NULL},
	{ "NewData", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefModifyItem, NewData), NULL, NULL, NULL},
	{ "notChangedSince", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefModifyItem, notChangedSince), NULL, NULL, NULL},
	{ "overrideAllowed", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefModifyItem, overrideAllowed), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefModifyItem, id), NULL, NULL, NULL},
	{ "itemID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefModifyItem, itemID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2SubsRefModifyItemClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ModifyItem");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SUBSREF_HREF, LASSO_IDWSF2_SUBSREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_subsref_modify_item_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SubsRefModifyItemClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SubsRefModifyItem),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2SubsRefModifyItem", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_subsref_modify_item_new:
 *
 * Creates a new #LassoIdWsf2SubsRefModifyItem object.
 *
 * Return value: a newly created #LassoIdWsf2SubsRefModifyItem object
 **/
LassoIdWsf2SubsRefModifyItem*
lasso_idwsf2_subsref_modify_item_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM, NULL);
}
