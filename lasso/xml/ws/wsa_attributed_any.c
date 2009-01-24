/* $Id: wsa_attributed_any.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "wsa_attributed_any.h"

/*
 * Schema fragment (ws-addr.xsd):
 *
 * <xs:complexType name="AttributedAnyType" mixed="false">
 *   <xs:sequence>
 *     <xs:any namespace="##any" processContents="lax" minOccurs="1" maxOccurs="1"/>
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsAddrAttributedAny, any), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsAddrAttributedAny, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsAddrAttributedAny *node)
{
	node->any = NULL;
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsAddrAttributedAnyClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ProblemHeader");
	lasso_node_class_set_ns(nclass, LASSO_WSA_HREF, LASSO_WSA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsa_attributed_any_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsAddrAttributedAnyClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsAddrAttributedAny),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsAddrAttributedAny", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsa_attributed_any_new:
 *
 * Creates a new #LassoWsAddrAttributedAny object.
 *
 * Return value: a newly created #LassoWsAddrAttributedAny object
 **/
LassoWsAddrAttributedAny*
lasso_wsa_attributed_any_new()
{
	return g_object_new(LASSO_TYPE_WSA_ATTRIBUTED_ANY, NULL);
}
