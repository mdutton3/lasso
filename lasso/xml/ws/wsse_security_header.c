/* $Id: wsse_security_header.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "wsse_security_header.h"
#include "../idwsf_strings.h"
#include "../../registry.h"

/*
 * Schema fragment (oasis-200401-wss-wssecurity-secext-1.0.xsd):
 *
 * <xs:complexType name="SecurityHeaderType">
 *   <xs:annotation>
 *     <xs:documentation>This complexType defines header block to use for security-relevant
 *             data directed at a specific SOAP actor.</xs:documentation>
 *     </xs:annotation>
 *     <xs:sequence>
 *       <xs:any processContents="lax" minOccurs="0" maxOccurs="unbounded">
 *         <xs:annotation>
 *           <xs:documentation>The use of "any" is to allow extensibility and different
 *                   forms of security data.</xs:documentation>
 *           </xs:annotation>
 *         </xs:any>
 *       </xs:sequence>
 *       <xs:anyAttribute namespace="##other" processContents="lax"/>
 *     </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsSec1SecurityHeader, any), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsSec1SecurityHeader, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsSec1SecurityHeader *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsSec1SecurityHeaderClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);
	guint i;
	const char *namespaces[] = {
		"http://schemas.xmlsoap.org/ws/2002/04/secext",
		"http://schemas.xmlsoap.org/ws/2002/07/secext",
		"http://schemas.xmlsoap.org/ws/2002/12/secext",
		"http://schemas.xmlsoap.org/ws/2003/06/secext",
		"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
		"http://www.docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	};

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Security");
	lasso_node_class_set_ns(nclass, LASSO_WSSE1_HREF, LASSO_WSSE1_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	/* Wsse has lots of namespaces defined */
	for (i=0; i < G_N_ELEMENTS(namespaces); i++) {
		lasso_registry_default_add_direct_mapping(namespaces[i], "Security", LASSO_LASSO_HREF, "LassoWsSec1SecurityHeader");
	}
}

GType
lasso_wsse_security_header_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsSec1SecurityHeaderClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsSec1SecurityHeader),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsSec1SecurityHeader", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsse_security_header_new:
 *
 * Creates a new #LassoWsSec1SecurityHeader object.
 *
 * Return value: a newly created #LassoWsSec1SecurityHeader object
 **/
LassoWsSec1SecurityHeader*
lasso_wsse_security_header_new()
{
	return g_object_new(LASSO_TYPE_WSSE_SECURITY_HEADER, NULL);
}
