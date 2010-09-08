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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "private.h"
#include "is_select.h"
#include "./idwsf_strings.h"

/**
 * SECTION:is_select
 * @short_description: &lt;is:Select&gt;
 *
 * <figure><title>Schema fragment for is:Select</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Select" type="SelectType"/>
 * <xs:complexType name="SelectType">
 *   <xs:complexContent>
 *     <xs:extension base="InquiryElementType">
 *       <xs:sequence>
 *         <xs:element name="Item" minOccurs="2" maxOccurs="unbounded"/>
 *       </xs:sequence>
 *       <xs:attribute name="multiple" type="xs:boolean" use="optional" default="false"/>
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
	{ "Item", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoIsSelect, Item), NULL, NULL, NULL},
	{ "multiple", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoIsSelect, multiple), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIsSelectClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Select");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_select_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsSelectClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsSelect),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsSelect", &this_info, 0);
	}
	return this_type;
}

LassoIsSelect*
lasso_is_select_new()
{
	LassoIsSelect *node;

	node = g_object_new(LASSO_TYPE_IS_SELECT, NULL);

	return node;
}
