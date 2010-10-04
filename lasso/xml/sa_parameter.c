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
#include "sa_parameter.h"
#include "./idwsf_strings.h"

/**
 * SECTION:sa_parameter
 * @short_description: &lt;sa:Parameter&gt;
 *
 * <figure><title>Schema fragment for sa:Parameter</title>
 * <programlisting><![CDATA[
 *
 *  <xs:element name="Parameter" minOccurs="0" maxOccurs="unbounded">
 *  <xs:complexType>
 *    <xs:simpleContent>
 *      <xs:extension base="xs:string">
 *        <xs:attribute name="name" type="xs:string" use="required"/>
 *      </xs:extension>
 *    </xs:simpleContent>
 *  </xs:complexType>
 *  </xs:element>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "content", SNIPPET_TEXT_CHILD, G_STRUCT_OFFSET(LassoSaParameter, content), NULL, NULL, NULL},
	{ "name", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSaParameter, name), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaParameterClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Parameter");
	lasso_node_class_set_ns(nclass, LASSO_SA_HREF, LASSO_SA_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_sa_parameter_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaParameterClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaParameter),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaParameter", &this_info, 0);
	}
	return this_type;
}

LassoSaParameter*
lasso_sa_parameter_new(const char *content, const char *name)
{
	LassoSaParameter *node;

	g_return_val_if_fail(content != NULL, NULL);
	g_return_val_if_fail(name != NULL, NULL);

	node = g_object_new(LASSO_TYPE_SA_PARAMETER, NULL);
	node->content = g_strdup(content);
	node->name = g_strdup(name);

	return node;
}
