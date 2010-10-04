/* $Id: dst_result_query_base.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "dst_result_query_base.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:dst_result_query_base
 * @short_description: &lt;dst:ResultQueryBase&gt;
 *
 * <figure><title>Schema fragment for dst:ResultQueryBase</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ResultQueryBaseType">
 *   <xs:sequence>
 *     <xs:element ref="dst:ChangeFormat" minOccurs="0" maxOccurs="2"/>
 *   </xs:sequence>
 *   <xs:attributeGroup ref="dst:selectQualif"/>
 *   <xs:attribute ref="lu:itemIDRef" use="optional"/>
 *   <xs:attribute name="contingency" use="optional" type="xs:boolean"/>
 *   <xs:attribute name="includeCommonAttributes" use="optional" type="xs:boolean"
 *           default="0"/>
 *   <xs:attribute name="changedSince" use="optional" type="xs:dateTime"/>
 *   <xs:attribute ref="lu:itemID" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "ChangeFormat", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, ChangeFormat), NULL, NULL, NULL},
	{ "itemIDRef", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, itemIDRef), NULL, NULL, NULL},
	{ "contingency", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, contingency), NULL, NULL, NULL},
	{ "includeCommonAttributes", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, includeCommonAttributes), NULL, NULL, NULL},
	{ "changedSince", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, changedSince), NULL, NULL, NULL},
	{ "itemID", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, itemID), NULL, NULL, NULL},
	{ "objectType", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, objectType), NULL, NULL, NULL},
	{ "predefined", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2DstResultQueryBase, predefined), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DstResultQueryBaseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ResultQueryBase");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DST_HREF, LASSO_IDWSF2_DST_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_dst_result_query_base_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DstResultQueryBaseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DstResultQueryBase),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DstResultQueryBase", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_dst_result_query_base_new:
 *
 * Creates a new #LassoIdWsf2DstResultQueryBase object.
 *
 * Return value: a newly created #LassoIdWsf2DstResultQueryBase object
 **/
LassoIdWsf2DstResultQueryBase*
lasso_idwsf2_dst_result_query_base_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE, NULL);
}
