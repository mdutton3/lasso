/* $Id: wsse_security_token_reference.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "wsse_security_token_reference.h"

/*
 * Schema fragment (oasis-200401-wss-wssecurity-secext-1.0.xsd):
 *
 * <xs:complexType name="SecurityTokenReferenceType">
 *   <xs:annotation>
 *     <xs:documentation>This type is used reference a security token.</xs:documentation>
 *     </xs:annotation>
 *     <xs:choice minOccurs="0" maxOccurs="unbounded">
 *       <xs:any processContents="lax"/>
 *     </xs:choice>
 *     <xs:attribute ref="wsu:Id"/>
 *     <xs:attribute ref="wsse:Usage"/>
 *     <xs:anyAttribute namespace="##other" processContents="lax"/>
 *   </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Id", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoWsSec1SecurityTokenReference, Id) },
	{ "Usage", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoWsSec1SecurityTokenReference, Usage) },
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsSec1SecurityTokenReference, attributes) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsSec1SecurityTokenReference *node)
{
	node->Id = NULL;
	node->Usage = NULL;
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsSec1SecurityTokenReferenceClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SecurityTokenReference");
	lasso_node_class_set_ns(nclass, LASSO_WSSE1_HREF, LASSO_WSSE1_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsse_security_token_reference_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsSec1SecurityTokenReferenceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsSec1SecurityTokenReference),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsSec1SecurityTokenReference", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsse_security_token_reference_new:
 *
 * Creates a new #LassoWsSec1SecurityTokenReference object.
 *
 * Return value: a newly created #LassoWsSec1SecurityTokenReference object
 **/
LassoWsSec1SecurityTokenReference*
lasso_wsse_security_token_reference_new()
{
	return g_object_new(LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE, NULL);
}
