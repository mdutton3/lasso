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

#include "../private.h"
#include "saml2_proxy_restriction.h"

/**
 * SECTION:saml2_proxy_restriction
 * @short_description: &lt;saml2:ProxyRestriction&gt;
 *
 * <figure><title>Schema fragment for saml2:ProxyRestriction</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="ProxyRestrictionType">
 *   <complexContent>
 *     <extension base="saml:ConditionAbstractType">
 *       <sequence>
 *         <element ref="saml:Audience" minOccurs="0" maxOccurs="unbounded"/>
 *       </sequence>
 *       <attribute name="Count" type="nonNegativeInteger" use="optional"/>
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
	{ "Audience", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSaml2ProxyRestriction, Audience), NULL, NULL, NULL},
	{ "Count", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoSaml2ProxyRestriction, Count), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaml2ProxyRestrictionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ProxyRestriction");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml2_proxy_restriction_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2ProxyRestrictionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2ProxyRestriction),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML2_CONDITION_ABSTRACT,
				"LassoSaml2ProxyRestriction", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml2_proxy_restriction_new:
 *
 * Creates a new #LassoSaml2ProxyRestriction object.
 *
 * Return value: a newly created #LassoSaml2ProxyRestriction object
 **/
LassoNode*
lasso_saml2_proxy_restriction_new()
{
	return g_object_new(LASSO_TYPE_SAML2_PROXY_RESTRICTION, NULL);
}
