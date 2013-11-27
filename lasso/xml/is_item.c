/* $Id$
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

#include "private.h"
#include "is_item.h"
#include "idwsf_strings.h"

/**
 * SECTION:is_item
 * @short_description: &lt;is:Hint&gt;
 *
 * <figure><title>Schema fragment for is:Hint</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Hint" type="xs:string"/>
 * <xs:element name="Item" minOccurs="2" maxOccurs="unbounded">
 *   <xs:complexType>
 *     <xs:sequence>
 *       <xs:element ref="Hint" minOccurs="0"/>
 *     </xs:sequence>
 *     <xs:attribute name="label" type="xs:string" use="optional"/>
 *     <xs:attribute name="value" type="xs:NMTOKEN" use="required"/>
 *   </xs:complexType>
 * </xs:element>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Hint", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoIsItem, Hint), NULL, NULL, NULL},
	{ "label", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsItem, label), NULL, NULL, NULL},
	{ "value", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsItem, value), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIsItemClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Item");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_item_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsItemClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsItem),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsItem", &this_info, 0);
	}
	return this_type;
}

LassoIsItem*
lasso_is_item_new(const char *value)
{
	LassoIsItem *node;

	node = g_object_new(LASSO_TYPE_IS_ITEM, NULL);

	node->value = g_strdup(value);

	return node;
}
