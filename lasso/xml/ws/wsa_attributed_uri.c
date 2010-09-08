/* $Id: wsa_attributed_uri.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "wsa_attributed_uri.h"
#include "../idwsf_strings.h"
#include "../../registry.h"

/*
 * Schema fragment (ws-addr.xsd):
 *
 * <xs:complexType name="AttributedURIType" mixed="false">
 *   <xs:simpleContent>
 *     <xs:extension base="xs:anyURI">
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
		G_STRUCT_OFFSET(LassoWsAddrAttributedURI, content), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsAddrAttributedURI, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsAddrAttributedURI *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsAddrAttributedURIClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AttributedURI");
	lasso_node_class_set_ns(nclass, LASSO_WSA_HREF, LASSO_WSA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsa_attributed_uri_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsAddrAttributedURIClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsAddrAttributedURI),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsAddrAttributedURI", &this_info, 0);
		lasso_registry_default_add_direct_mapping(LASSO_WSA_HREF, "Action",
				LASSO_LASSO_HREF, "LassoWsAddrAttributedURI");
		lasso_registry_default_add_direct_mapping(LASSO_WSA_HREF, "MessageID",
				LASSO_LASSO_HREF, "LassoWsAddrAttributedURI");
		lasso_registry_default_add_direct_mapping(LASSO_WSA_HREF, "To", LASSO_LASSO_HREF,
				"LassoWsAddrAttributedURI");
	}
	return this_type;
}

/**
 * lasso_wsa_attributed_uri_new:
 *
 * Creates a new #LassoWsAddrAttributedURI object.
 *
 * Return value: a newly created #LassoWsAddrAttributedURI object
 **/
LassoWsAddrAttributedURI*
lasso_wsa_attributed_uri_new()
{
	return g_object_new(LASSO_TYPE_WSA_ATTRIBUTED_URI, NULL);
}


/**
 * lasso_wsa_attributed_uri_new_with_string:
 * @content: a content string
 *
 * Creates a new #LassoWsAddrAttributedURI object and initializes it
 * with @content as content.
 *
 * Return value: a newly created #LassoWsAddrAttributedURI object
 **/
LassoWsAddrAttributedURI*
lasso_wsa_attributed_uri_new_with_string(const char *content)
{
	LassoWsAddrAttributedURI *object;
	object = g_object_new(LASSO_TYPE_WSA_ATTRIBUTED_URI, NULL);
	object->content = g_strdup(content);
	return object;
}
