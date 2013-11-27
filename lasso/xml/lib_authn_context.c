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
#include "lib_authn_context.h"

/**
 * SECTION:lib_authn_context
 * @short_description: &lt;lib:AuthnContext&gt;
 *
 * <figure><title>Schema fragment for lib:AuthnContext</title>
 * <programlisting><![CDATA[
 * <xs:element name="AuthnContext">
 *   <xs:complexType>
 *     <xs:sequence>
 *       <xs:element name="AuthnContextClassRef" type="xs:anyURI" minOccurs="0"/>
 *       <xs:choice>
 *         <xs:element ref="ac:AuthenticationContextStatement"/>
 *         <xs:element name="AuthnContextStatementRef" type="xs:anyURI"/>
 *       </xs:choice>
 *     </xs:sequence>
 *   </xs:complexType>
 * </xs:element>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AuthnContextClassRef", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnContext, AuthnContextClassRef), NULL, NULL, NULL},
	{ "AuthnContextStatementRef", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnContext, AuthnContextStatementRef), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibAuthnContextClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnContext");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_authn_context_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthnContextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnContext),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibAuthnContext", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_authn_context_new:
 *
 * Creates a new #LassoLibAuthnContext object.
 *
 * Return value: a newly created #LassoLibAuthnContext object
 **/
LassoNode*
lasso_lib_authn_context_new() {
	return g_object_new(LASSO_TYPE_LIB_AUTHN_CONTEXT, NULL);
}
