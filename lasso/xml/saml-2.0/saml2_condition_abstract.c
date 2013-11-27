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
#include "../../registry.h"
#include "saml2_condition_abstract.h"

/**
 * SECTION:saml2_condition_abstract
 * @short_description: &lt;saml2:ConditionAbstract&gt;
 *
 * <figure><title>Schema fragment for saml2:ConditionAbstract</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="ConditionAbstractType" abstract="true"/>
 * <element name="AudienceRestriction" type="saml:AudienceRestrictionType"/>
 * <complexType name="AudienceRestrictionType">
 *   <complexContent>
 *     <extension base="saml:ConditionAbstractType">
 *       <sequence>
 *         <element ref="saml:Audience" maxOccurs="unbounded"/>
 *       </sequence>
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
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoSaml2ConditionAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->node_data->keep_xmlnode = TRUE;
	lasso_node_class_set_nodename(nclass, "Condition");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml2_condition_abstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2ConditionAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2ConditionAbstract),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaml2ConditionAbstract", &this_info, 0);
		lasso_registry_default_add_direct_mapping(LASSO_SAML2_ASSERTION_HREF, "Condition",
				LASSO_LASSO_HREF, "LassoSaml2ConditionAbstract");
	}
	return this_type;
}

/**
 * lasso_saml2_condition_abstract_new:
 *
 * Creates a new #LassoSaml2ConditionAbstract object.
 *
 * Return value: a newly created #LassoSaml2ConditionAbstract object
 **/
LassoNode*
lasso_saml2_condition_abstract_new()
{
	return g_object_new(LASSO_TYPE_SAML2_CONDITION_ABSTRACT, NULL);
}
