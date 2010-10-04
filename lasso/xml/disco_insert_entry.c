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
#include "disco_insert_entry.h"
#include "./idwsf_strings.h"
#include "../utils.h"

/**
 * SECTION:disco_insert_entry
 * @short_description: &lt;disco:InsertEntryType&gt;
 *
 * <figure><title>Schema fragment for disco:InsertEntryType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="InsertEntryType">
 *   <xs:sequence>
 *     <xs:element ref="ResourceOffering"/>
 *     <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceOffering", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoInsertEntry, ResourceOffering), NULL, NULL, NULL},
	{ "", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDiscoInsertEntry, any), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoInsertEntryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "InsertEntry");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_insert_entry_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoInsertEntryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoInsertEntry),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoInsertEntry", &this_info, 0);
	}
	return this_type;
}

LassoDiscoInsertEntry*
lasso_disco_insert_entry_new(LassoDiscoResourceOffering *resourceOffering)
{
	LassoDiscoInsertEntry *insertEntry;

	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering) == TRUE, NULL);

	insertEntry = g_object_new(LASSO_TYPE_DISCO_INSERT_ENTRY, NULL);
	lasso_assign_gobject(insertEntry->ResourceOffering, resourceOffering);

	return insertEntry;
}
