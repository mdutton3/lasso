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
#include "saml_authority_binding.h"

/**
 * SECTION:saml_authority_binding
 * @short_description: &lt;saml:AuthorityBinding&gt;
 *
 * <figure><title>Schema fragment for saml:AuthorityBinding</title>
 * <programlisting><![CDATA[
 *
 * <element name="AuthorityBinding" type="saml:AuthorityBindingType"/>
 * <complexType name="AuthorityBindingType">
 *   <attribute name="AuthorityKind" type="QName" use="required"/>
 *   <attribute name="Location" type="anyURI" use="required"/>
 *   <attribute name="Binding" type="anyURI" use="required"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AuthorityKind", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAuthorityBinding, AuthorityKind), NULL, NULL, NULL},
	{ "Location", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAuthorityBinding, Location), NULL, NULL, NULL},
	{ "Binding", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAuthorityBinding, Binding), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlAuthorityBindingClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthorityBinding");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_authority_binding_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAuthorityBindingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAuthorityBinding),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAuthorityBinding", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_authority_binding_new:
 *
 * Creates a new #LassoSamlAuthorityBinding object.
 *
 * Return value: a newly created #LassoSamlAuthorityBinding object
 **/
LassoNode*
lasso_saml_authority_binding_new()
{
	return g_object_new(LASSO_TYPE_SAML_AUTHORITY_BINDING, NULL);
}
