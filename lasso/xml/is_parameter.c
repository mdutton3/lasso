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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "private.h"
#include "is_parameter.h"
#include "./idwsf_strings.h"

/**
 * SECTION:is_parameter
 * @short_description: &lt;is:ParameterType&gt;
 *
 * <figure><title>Schema fragment for is:ParameterType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ParameterType">
 *   <xs:attribute name="name" type="xs:ID" use="required"/>
 *   <xs:attribute name="value" type="xs:string" use="required"/>
 * </xs:complexType>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "name", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsParameter, name), NULL, NULL, NULL},
	{ "value", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsParameter, value), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIsParameterClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Parameter");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_parameter_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsParameterClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsParameter),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsParameter", &this_info, 0);
	}
	return this_type;
}

LassoIsParameter*
lasso_is_parameter_new(const char *name, const char *value)
{
	LassoIsParameter *node;

	node = g_object_new(LASSO_TYPE_IS_PARAMETER, NULL);

	node->name = g_strdup(name);
	node->value = g_strdup(value);

	return node;
}
