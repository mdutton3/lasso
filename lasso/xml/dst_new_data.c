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
#include "dst_new_data.h"
#include "./idwsf_strings.h"

/**
 * SECTION:dst_new_data
 * @short_description: &lt;dst:NewData&gt;
 *
 * <figure><title>Schema fragment for dst:NewData</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="NewData" minOccurs="0">
 *     <xs:complexType>
 *         <xs:sequence>
 *             <xs:any minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *     </xs:complexType>
 * </xs:element>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_XMLNODES, G_STRUCT_OFFSET(LassoDstNewData, any), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDstNewDataClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nodeClass, "NewData");
	lasso_node_class_add_snippets(nodeClass, schema_snippets);
}

GType
lasso_dst_new_data_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstNewDataClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstNewData),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstNewData", &this_info, 0);
	}
	return this_type;
}

LassoDstNewData*
lasso_dst_new_data_new()
{
	LassoDstNewData *newData;

	newData = g_object_new(LASSO_TYPE_DST_NEW_DATA, NULL);

	return newData;
}

