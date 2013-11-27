/* $Id: wsse_transformation_parameters.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "wsse_transformation_parameters.h"
#include "../idwsf_strings.h"

/*
 * Schema fragment (oasis-200401-wss-wssecurity-secext-1.0.xsd):
 *
 * <xs:complexType name="TransformationParametersType">
 *   <xs:annotation>
 *     <xs:documentation>This complexType defines a container for elements to
 *             be specified from any namespace as properties/parameters
 *             of a DSIG transformation.</xs:documentation>
 *     </xs:annotation>
 *     <xs:sequence>
 *       <xs:any processContents="lax" minOccurs="0" maxOccurs="unbounded">
 *         <xs:annotation>
 *           <xs:documentation>The use of "any" is to allow extensibility from
 *                   any namespace.</xs:documentation>
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
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsSec1TransformationParameters, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsSec1TransformationParameters *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsSec1TransformationParametersClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "TransformationParameters");
	lasso_node_class_set_ns(nclass, LASSO_WSSE1_HREF, LASSO_WSSE1_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsse_transformation_parameters_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsSec1TransformationParametersClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsSec1TransformationParameters),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsSec1TransformationParameters", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsse_transformation_parameters_new:
 *
 * Creates a new #LassoWsSec1TransformationParameters object.
 *
 * Return value: a newly created #LassoWsSec1TransformationParameters object
 **/
LassoWsSec1TransformationParameters*
lasso_wsse_transformation_parameters_new()
{
	return g_object_new(LASSO_TYPE_WSSE_TRANSFORMATION_PARAMETERS, NULL);
}
