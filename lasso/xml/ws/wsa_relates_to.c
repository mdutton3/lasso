/* $Id: wsa_relates_to.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "wsa_relates_to.h"
#include "../idwsf_strings.h"

/*
 * Schema fragment (ws-addr.xsd):
 *
 * <xs:complexType name="RelatesToType" mixed="false">
 *   <xs:simpleContent>
 *     <xs:extension base="xs:anyURI">
 *       <xs:attribute name="RelationshipType" type="tns:RelationshipTypeOpenEnum"
 *               use="optional" default="http://www.w3.org/2005/08/addressing/reply"/>
 *       <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:extension>
 *   </xs:simpleContent>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "content", SNIPPET_TEXT_CHILD,
		G_STRUCT_OFFSET(LassoWsAddrRelatesTo, content), NULL, NULL, NULL},
	{ "RelationshipType", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoWsAddrRelatesTo, RelationshipType), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsAddrRelatesTo, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsAddrRelatesTo *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsAddrRelatesToClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RelatesTo");
	lasso_node_class_set_ns(nclass, LASSO_WSA_HREF, LASSO_WSA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsa_relates_to_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsAddrRelatesToClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsAddrRelatesTo),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsAddrRelatesTo", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsa_relates_to_new:
 *
 * Creates a new #LassoWsAddrRelatesTo object.
 *
 * Return value: a newly created #LassoWsAddrRelatesTo object
 **/
LassoWsAddrRelatesTo*
lasso_wsa_relates_to_new()
{
	return g_object_new(LASSO_TYPE_WSA_RELATES_TO, NULL);
}


/**
 * lasso_wsa_relates_to_new_with_string:
 * @content: a content string
 *
 * Creates a new #LassoWsAddrRelatesTo object and initializes it
 * with @content as content.
 *
 * Return value: a newly created #LassoWsAddrRelatesTo object
 **/
LassoWsAddrRelatesTo*
lasso_wsa_relates_to_new_with_string(char *content)
{
	LassoWsAddrRelatesTo *object;
	object = g_object_new(LASSO_TYPE_WSA_RELATES_TO, NULL);
	object->content = g_strdup(content);
	return object;
}
