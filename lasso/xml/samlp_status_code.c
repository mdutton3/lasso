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
#include "samlp_status_code.h"

/**
 * SECTION:samlp_status_code
 * @short_description: &lt;samlp:StatusCode&gt;
 *
 * <figure><title>Schema fragment for samlp:StatusCode</title>
 * <programlisting><![CDATA[
 *
 * <element name="StatusCode" type="samlp:StatusCodeType"/>
 * <complexType name="StatusCodeType">
 *   <sequence>
 *     <element ref="samlp:StatusCode" minOccurs="0"/>
 *   </sequence>
 *   <attribute name="Value" type="QName" use="required"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "StatusCode", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlpStatusCode, StatusCode), NULL, NULL, NULL},
	{ "Value", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlpStatusCode, Value), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoSamlpStatusCodeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "StatusCode");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp_status_code_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpStatusCodeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpStatusCode),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlpStatusCode",
				&this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp_status_code_new:
 *
 * Creates a new #LassoSamlpStatusCode object.
 *
 * Return value: a newly created #LassoSamlpStatusCode object
 **/
LassoSamlpStatusCode*
lasso_samlp_status_code_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_STATUS_CODE, NULL);
}
