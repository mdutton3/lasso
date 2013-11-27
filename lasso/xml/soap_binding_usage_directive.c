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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "private.h"
#include "soap_binding_usage_directive.h"
#include "idwsf_strings.h"

/**
 * SECTION:soap_binding_usage_directive
 * @short_description: &lt;soapbinding:UsageDirectiveType&gt;
 *
 * <figure><title>Schema fragment for soapbinding:UsageDirectiveType</title>
 * <programlisting><![CDATA[
 * <xs:complexType name="UsageDirectiveType">
 *     <xs:sequence>
 *         <xs:any namespace="##other" processContents="lax" maxOccurs="unbounded"/>
 *     </xs:sequence>
 *     <xs:attribute name="id" type="xs:ID" use="optional"/>
 *     <xs:attribute name="ref" type="xs:IDREF" use="required"/>
 *     <xs:attribute ref="S:mustUnderstand" use="optional"/>
 *     <xs:attribute ref="S:actor" use="optional"/>
 * </xs:complexType>
 * <xs:element name="UsageDirective" type="UsageDirectiveType"/>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSoapBindingUsageDirective, other), NULL, NULL, NULL},
	{ "ref", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingUsageDirective, ref), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSoapBindingUsageDirective, id), NULL, NULL, NULL},
	{ "mustUnderstand", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSoapBindingUsageDirective, mustUnderstand), NULL, NULL, NULL},
	{ "actor", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSoapBindingUsageDirective, actor), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapBindingUsageDirectiveClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "UsageDirective");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_BINDING_HREF, LASSO_SOAP_BINDING_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_binding_usage_directive_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapBindingUsageDirectiveClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapBindingUsageDirective),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapBindingUsageDirective", &this_info, 0);
	}
	return this_type;
}

LassoSoapBindingUsageDirective*
lasso_soap_binding_usage_directive_new(const gchar *ref)
{
	LassoSoapBindingUsageDirective *node;

	node = g_object_new(LASSO_TYPE_SOAP_BINDING_USAGE_DIRECTIVE, NULL);

	node->ref = g_strdup(ref);

	return node;
}
