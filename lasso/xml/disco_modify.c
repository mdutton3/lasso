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
#include "disco_modify.h"
#include "./idwsf_strings.h"

/**
 * SECTION:disco_modify
 * @short_description: &lt;disco:Modify&gt;
 *
 * <figure><title>Schema fragment for disco:Modify</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="Modify" type="ModifyType"/>
 * <xs:complexType name="ModifyType">
 *   <xs:sequence>
 *     <xs:group ref="ResourceIDGroup"/>
 *     <xs:element name="InsertEntry" type="InsertEntryType" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="RemoveEntry" type="RemoveEntryType" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 *
 * <xs:group name="ResourceIDGroup">
 *   <xs:sequence>
 *     <xs:choice minOccurs="0" maxOccurs="1">
 *       <xs:element ref="ResourceID"/>
 *       <xs:element ref="EncryptedResourceID"/>
 *     </xs:choice>
 *   </xs:sequence>
 * </xs:group>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDiscoModify, ResourceID), NULL, NULL, NULL},
	{ "EncryptedResourceID", SNIPPET_NODE, \
		G_STRUCT_OFFSET(LassoDiscoModify, EncryptedResourceID), NULL, NULL, NULL},
	{ "InsertEntry", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDiscoModify, InsertEntry), NULL, NULL, NULL},
	{ "RemoveEntry", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDiscoModify, RemoveEntry), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDiscoModify, id), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoModifyClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Modify");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_modify_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoModifyClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoModify),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoModify", &this_info, 0);
	}
	return this_type;
}

LassoDiscoModify*
lasso_disco_modify_new()
{
	LassoDiscoModify *node;

	node = g_object_new(LASSO_TYPE_DISCO_MODIFY, NULL);

	return node;
}
