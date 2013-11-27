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
#include "disco_resource_id.h"
#include "idwsf_strings.h"

/**
 * SECTION:disco_resource_id
 * @short_description: &lt;disco:ResourceID&gt;
 *
 * <figure><title>Schema fragment for disco:ResourceID</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="ResourceID" type="ResourceIDType"/>
 * <xs:complexType name="ResourceIDType">
 *     <xs:simpleContent>
 *        <xs:extension base="xs:anyURI">
 *           <xs:attribute name="id" type="xs:ID" use="optional"/>
 *        </xs:extension>
 *     </xs:simpleContent>
 *  </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDiscoResourceID, id), NULL, NULL, NULL},
	{ "", SNIPPET_TEXT_CHILD, G_STRUCT_OFFSET(LassoDiscoResourceID, content), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoResourceIDClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ResourceID");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_resource_id_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoResourceIDClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoResourceID),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoResourceID", &this_info, 0);
	}
	return this_type;
}

LassoDiscoResourceID*
lasso_disco_resource_id_new(const gchar *content)
{
	LassoDiscoResourceID *node;

	g_return_val_if_fail(content != NULL, NULL);

	node = g_object_new(LASSO_TYPE_DISCO_RESOURCE_ID, NULL);
	node->content = g_strdup(content);

	return node;
}
