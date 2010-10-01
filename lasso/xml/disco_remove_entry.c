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
#include "disco_remove_entry.h"
#include "./idwsf_strings.h"

/**
 * SECTION:disco_remove_entry
 * @short_description: &lt;disco:RemoveEntryType&gt;
 *
 * <figure><title>Schema fragment for disco:RemoveEntryType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="RemoveEntryType">
 *   <xs:attribute name="entryID" type="IDReferenceType" use="required"/>
 * </xs:complexType>
 *
 * Schema fragment (liberty-idwsf-utility-1.0-errata-v1.0.xsd)
 *
 * <xs:simpleType name="IDReferenceType">
 *   <xs:restriction base="xs:string"/>
 * </xs:simpleType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "entryID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDiscoRemoveEntry, entryID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDiscoRemoveEntryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RemoveEntry");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_remove_entry_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoRemoveEntryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoRemoveEntry),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoRemoveEntry", &this_info, 0);
	}
	return this_type;
}

LassoDiscoRemoveEntry*
lasso_disco_remove_entry_new(const gchar *entryID)
{
	LassoDiscoRemoveEntry *entry;

	g_return_val_if_fail(entryID != NULL, NULL);

	entry = g_object_new(LASSO_TYPE_DISCO_REMOVE_ENTRY, NULL);
	entry->entryID = g_strdup(entryID);

	return entry;
}
