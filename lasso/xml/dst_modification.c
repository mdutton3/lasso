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
#include "dst_modification.h"
#include "./idwsf_strings.h"

/**
 * SECTION:dst_modification
 * @short_description: &lt;dst:Modification&gt;
 *
 * <figure><title>Schema fragment for dst:Modification</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Modification" maxOccurs="unbounded">
 * <xs:complexType>
 *     <xs:sequence>
 *         <xs:element name="Select" type="SelectType"/>
 *         <xs:element name="NewData" minOccurs="0">
 *             <xs:complexType>
 *                 <xs:sequence>
 *                     <xs:any minOccurs="0" maxOccurs="unbounded"/>
 *                 </xs:sequence>
 *             </xs:complexType>
 *         </xs:element>
 *     </xs:sequence>
 *     <xs:attribute name="id" type="xs:ID"/>
 *     <xs:attribute name="notChangedSince" type="xs:dateTime"/>
 *     <xs:attribute name="overrideAllowed" type="xs:boolean" default="0"/>
 * </xs:complexType>
 * </xs:element>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Select", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoDstModification, Select), NULL, NULL, NULL},
	{ "NewData", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModification, NewData), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModification, id), NULL, NULL, NULL},
	{ "notChangedSince", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModification,
			notChangedSince), NULL, NULL, NULL },
	{ "overrideAllowed", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN, G_STRUCT_OFFSET(LassoDstModification,
			overrideAllowed), NULL, NULL, NULL },
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDstModificationClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nodeClass, "Modification");
	lasso_node_class_add_snippets(nodeClass, schema_snippets);
}

GType
lasso_dst_modification_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstModificationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstModification),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstModification", &this_info, 0);
	}
	return this_type;
}

LassoDstModification*
lasso_dst_modification_new(const char *select)
{
	LassoDstModification *modification;

	g_return_val_if_fail(select != NULL, NULL);

	modification = g_object_new(LASSO_TYPE_DST_MODIFICATION, NULL);

	modification->Select = g_strdup(select);

	return modification;
}

