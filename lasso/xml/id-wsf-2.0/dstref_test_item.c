/* $Id: dstref_test_item.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "dstref_test_item.h"
#include "idwsf2_strings.h"

/**
 * SECTION:dstref_test_item
 * @short_description: &lt;dstref:TestItem&gt;
 *
 * <figure><title>Schema fragment for dstref:TestItem</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="TestItemType">
 *   <xs:complexContent>
 *     <xs:extension base="dst:TestItemBaseType">
 *       <xs:sequence>
 *         <xs:element name="TestOp" minOccurs="0" maxOccurs="1" type="dstref:TestOpType"/>
 *       </xs:sequence>
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
	{ "TestOp", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DstRefTestItem, TestOp), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DstRefTestItemClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "TestItem");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DSTREF_HREF, LASSO_IDWSF2_DSTREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_dstref_test_item_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DstRefTestItemClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DstRefTestItem),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_DST_TEST_ITEM_BASE,
				"LassoIdWsf2DstRefTestItem", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_dstref_test_item_new:
 *
 * Creates a new #LassoIdWsf2DstRefTestItem object.
 *
 * Return value: a newly created #LassoIdWsf2DstRefTestItem object
 **/
LassoIdWsf2DstRefTestItem*
lasso_idwsf2_dstref_test_item_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DSTREF_TEST_ITEM, NULL);
}
