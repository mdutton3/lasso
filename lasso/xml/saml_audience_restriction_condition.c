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
#include "saml_audience_restriction_condition.h"

/*
 * schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):
 *
 * <element name="AudienceRestrictionCondition" type="saml:AudienceRestrictionConditionType"/>
 * <complexType name="AudienceRestrictionConditionType">
 *   <complexContent>
 *     <extension base="saml:ConditionAbstractType">
 *       <sequence>
 *         <element ref="saml:Audience" maxOccurs="unbounded"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 *
 * <element name="Audience" type="anyURI"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Audience", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoSamlAudienceRestrictionCondition, Audience), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlAudienceRestrictionConditionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AudienceRestrictionCondition");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_audience_restriction_condition_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAudienceRestrictionConditionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAudienceRestrictionCondition),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_CONDITION_ABSTRACT,
				"LassoSamlAudienceRestrictionCondition", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_audience_restriction_condition_new:
 *
 * Creates a new #LassoSamlAudienceRestrictionCondition object.
 *
 * Return value: a newly created #LassoSamlAudienceRestrictionCondition
 **/
LassoSamlAudienceRestrictionCondition*
lasso_saml_audience_restriction_condition_new()
{
	return g_object_new(LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION, NULL);
}


/**
 * lasso_saml_audience_restriction_condition_new_full:
 * @audience: a string which specify to which audience the restriction condition applies
 *
 * Creates a new #LassoSamlAudienceRestrictionCondition object and initializes
 * it with the parameters.
 *
 * Return value: a newly created #LassoSamlAudienceRestrictionCondition
 **/
LassoSamlAudienceRestrictionCondition*
lasso_saml_audience_restriction_condition_new_full(const char *audience)
{
	LassoSamlAudienceRestrictionCondition *condition;

	condition = lasso_saml_audience_restriction_condition_new();
	if (audience != NULL) {
		condition->Audience = g_list_append(condition->Audience, g_strdup(audience));
	}
	return condition;
}
