/* $Id: wsu_timestamp.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "wsu_timestamp.h"
#include "../idwsf_strings.h"

/*
 * Schema fragment (oasis-200401-wss-wssecurity-utility-1.0.xsd):
 *
 * <xs:complexType name="TimestampType">
 *   <xs:annotation>
 *     <xs:documentation>
 *       This complex type ties together the timestamp related elements into a composite type.
 *     </xs:documentation>
 *   </xs:annotation>
 *   <xs:sequence>
 *     <xs:element ref="wsu:Created" minOccurs="0"/>
 *     <xs:element ref="wsu:Expires" minOccurs="0"/>
 *     <xs:choice minOccurs="0" maxOccurs="unbounded">
 *       <xs:any namespace="##other" processContents="lax"/>
 *     </xs:choice>
 *   </xs:sequence>
 *   <xs:attributeGroup ref="wsu:commonAtts"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Created", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoWsUtil1Timestamp, Created), NULL, NULL, NULL},
	{ "Expires", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoWsUtil1Timestamp, Expires), NULL, NULL, NULL},
	{ "Id", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoWsUtil1Timestamp, Id), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsUtil1Timestamp, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsUtil1Timestamp *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsUtil1TimestampClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Timestamp");
	lasso_node_class_set_ns(nclass, LASSO_WSUTIL1_HREF, LASSO_WSUTIL1_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsu_timestamp_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsUtil1TimestampClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsUtil1Timestamp),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsUtil1Timestamp", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsu_timestamp_new:
 *
 * Creates a new #LassoWsUtil1Timestamp object.
 *
 * Return value: a newly created #LassoWsUtil1Timestamp object
 **/
LassoWsUtil1Timestamp*
lasso_wsu_timestamp_new()
{
	return g_object_new(LASSO_TYPE_WSU_TIMESTAMP, NULL);
}
