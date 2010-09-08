/* $Id: wsa_attributed_qname.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "wsa_attributed_qname.h"
#include "../idwsf_strings.h"

/*
 * Schema fragment (ws-addr.xsd):
 *
 * <xs:complexType name="AttributedQNameType" mixed="false">
 *   <xs:simpleContent>
 *     <xs:extension base="xs:QName">
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
		G_STRUCT_OFFSET(LassoWsAddrAttributedQName, content), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsAddrAttributedQName, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsAddrAttributedQName *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsAddrAttributedQNameClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ProblemHeaderQName");
	lasso_node_class_set_ns(nclass, LASSO_WSA_HREF, LASSO_WSA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsa_attributed_qname_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsAddrAttributedQNameClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsAddrAttributedQName),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsAddrAttributedQName", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsa_attributed_qname_new:
 *
 * Creates a new #LassoWsAddrAttributedQName object.
 *
 * Return value: a newly created #LassoWsAddrAttributedQName object
 **/
LassoWsAddrAttributedQName*
lasso_wsa_attributed_qname_new()
{
	return g_object_new(LASSO_TYPE_WSA_ATTRIBUTED_QNAME, NULL);
}


/**
 * lasso_wsa_attributed_qname_new_with_string:
 * @content: a content string.
 *
 * Creates a new #LassoWsAddrAttributedQName object and initializes it
 * with @content as content.
 *
 * Return value: a newly created #LassoWsAddrAttributedQName object
 **/
LassoWsAddrAttributedQName*
lasso_wsa_attributed_qname_new_with_string(char *content)
{
	LassoWsAddrAttributedQName *object;
	object = g_object_new(LASSO_TYPE_WSA_ATTRIBUTED_QNAME, NULL);
	object->content = g_strdup(content);
	return object;
}
