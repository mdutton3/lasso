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
#include "saml2_conditions.h"

/**
 * SECTION:saml2_conditions
 * @short_description: &lt;saml2:Conditions&gt;
 *
 * <figure><title>Schema fragment for saml2:Conditions</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="ConditionsType">
 *   <choice minOccurs="0" maxOccurs="unbounded">
 *     <element ref="saml:Condition"/>
 *     <element ref="saml:AudienceRestriction"/>
 *     <element ref="saml:OneTimeUse"/>
 *     <element ref="saml:ProxyRestriction"/>
 *   </choice>
 *   <attribute name="NotBefore" type="dateTime" use="optional"/>
 *   <attribute name="NotOnOrAfter" type="dateTime" use="optional"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Condition", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSaml2Conditions, Condition), NULL, NULL, NULL},
	{ "AudienceRestriction", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSaml2Conditions, AudienceRestriction), NULL, NULL, NULL},
	{ "OneTimeUse", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSaml2Conditions, OneTimeUse), NULL, NULL, NULL},
	{ "ProxyRestriction", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSaml2Conditions, ProxyRestriction), NULL, NULL, NULL},
	{ "NotBefore", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSaml2Conditions, NotBefore), NULL, NULL, NULL},
	{ "NotOnOrAfter", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSaml2Conditions, NotOnOrAfter), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSaml2ConditionsClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Conditions");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml2_conditions_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2ConditionsClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2Conditions),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaml2Conditions", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml2_conditions_new:
 *
 * Creates a new #LassoSaml2Conditions object.
 *
 * Return value: a newly created #LassoSaml2Conditions object
 **/
LassoNode*
lasso_saml2_conditions_new()
{
	return g_object_new(LASSO_TYPE_SAML2_CONDITIONS, NULL);
}
