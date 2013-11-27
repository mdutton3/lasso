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
#include "saml_attribute_statement.h"

/**
 * SECTION:saml_attribute_statement
 * @short_description: object mapping for a saml:AttributeStatement
 *
 * The schema fragment (oasis-sstc-saml-schema-assertion-1.1.xsd):
 * <figure>
 * <title>Schema fragment for saml:AttributeStatement</title>
 * <programlisting>
 * <![CDATA[
 * <element name="AttributeStatement" type="saml:AttributeStatementType"/>
 * <complexType name="AttributeStatementType">
 *   <complexContent>
 *     <extension base="saml:SubjectStatementAbstractType">
 *       <sequence>
 *         <element ref="saml:Attribute" maxOccurs="unbounded"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 * ]]>
 * </programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Attribute", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSamlAttributeStatement, Attribute), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlAttributeStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AttributeStatement");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_attribute_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAttributeStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAttributeStatement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
				"LassoSamlAttributeStatement",
				&this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_attribute_statement_new:
 *
 * Creates a new #LassoSamlAttributeStatement object.
 *
 * Return value: a newly created #LassoSamlAttributeStatement object
 **/
LassoSamlAttributeStatement*
lasso_saml_attribute_statement_new()
{
	return g_object_new(LASSO_TYPE_SAML_ATTRIBUTE_STATEMENT, NULL);
}
