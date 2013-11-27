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
#include "disco_encrypted_resource_id.h"
#include "idwsf_strings.h"

/**
 * SECTION:disco_encrypted_resource_id
 * @short_description: &lt;disco:EncryptedResourceID&gt;
 *
 * <figure><title>Schema fragment for disco:EncryptedResourceID</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="EncryptedResourceID" type="EncryptedResourceIDType"/>
 * <xs:complexType name="EncryptedResourceIDType">
 *    <xs:sequence>
 *       <xs:element ref="xenc:EncryptedData"/>
 *       <xs:element ref="xenc:EncryptedKey"/>
 *    </xs:sequence>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods	                                                   */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "EncryptedData", SNIPPET_XMLNODE,
		G_STRUCT_OFFSET(LassoDiscoEncryptedResourceID, EncryptedData), NULL,
		LASSO_XMLENC_PREFIX, LASSO_XMLENC_HREF},
	{ "EncryptedKey", SNIPPET_LIST_XMLNODES,
		G_STRUCT_OFFSET(LassoDiscoEncryptedResourceID, EncryptedKey), NULL,
		LASSO_XMLENC_PREFIX, LASSO_XMLENC_HREF},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions	                                 */
/*****************************************************************************/

static void
class_init(LassoDiscoEncryptedResourceIDClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "EncryptedResourceID");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_encrypted_resource_id_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoEncryptedResourceIDClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoEncryptedResourceID),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoEncryptedResourceID",
				&this_info, 0);
	}
	return this_type;
}

LassoDiscoEncryptedResourceID*
lasso_disco_encrypted_resource_id_new()
{
	LassoDiscoEncryptedResourceID *node;

	node = g_object_new(LASSO_TYPE_DISCO_ENCRYPTED_RESOURCE_ID, NULL);

	return node;
}
