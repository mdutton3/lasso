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
#include "saml_authentication_statement.h"

/**
 * SECTION:saml_authentication_statement
 * @short_description: &lt;saml:AuthenticationStatement&gt;
 *
 * <figure><title>Schema fragment for saml:AuthenticationStatement</title>
 * <programlisting><![CDATA[
 *
 * <element name="AuthenticationStatement" type="saml:AuthenticationStatementType"/>
 * <complexType name="AuthenticationStatementType">
 *   <complexContent>
 *     <extension base="saml:SubjectStatementAbstractType">
 *       <sequence>
 *         <element ref="saml:SubjectLocality" minOccurs="0"/>
 *         <element ref="saml:AuthorityBinding" minOccurs="0" maxOccurs="unbounded"/>
 *       </sequence>
 *       <attribute name="AuthenticationMethod" type="anyURI" use="required"/>
 *       <attribute name="AuthenticationInstant" type="dateTime" use="required"/>
 *     </extension>
 *   </complexContent>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "SubjectLocality", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlAuthenticationStatement, SubjectLocality), NULL, NULL, NULL},
	{ "AuthorityBinding", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSamlAuthenticationStatement, AuthorityBinding), NULL, NULL, NULL},
	{ "AuthenticationMethod", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAuthenticationStatement, AuthenticationMethod), NULL, NULL, NULL},
	{ "AuthenticationInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAuthenticationStatement, AuthenticationInstant), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlAuthenticationStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthenticationStatement");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_authentication_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAuthenticationStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAuthenticationStatement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
				"LassoSamlAuthenticationStatement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_authentication_statement_new:
 *
 * Creates a new #LassoSamlAuthenticationStatement object.
 *
 * Return value: a newly created #LassoSamlAuthenticationStatement object
 **/
LassoNode*
lasso_saml_authentication_statement_new()
{
	return g_object_new(LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT, NULL);
}
