/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lasso/xml/saml_conditions.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="Conditions" type="saml:ConditionsType"/>
<complexType name="ConditionsType">
  <choice minOccurs="0" maxOccurs="unbounded">
    <element ref="saml:AudienceRestrictionCondition"/>
    <element ref="saml:Condition"/>
  </choice>
  <attribute name="NotBefore" type="dateTime" use="optional"/>
  <attribute name="NotOnOrAfter" type="dateTime" use="optional"/>
</complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_saml_conditions_add_condition:
 * @node: the <saml:Conditions> node object
 * @condition: 
 * 
 * 
 **/
void
lasso_saml_conditions_add_condition(LassoSamlConditions *node,
				    LassoSamlConditionAbstract *condition)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_CONDITIONS(node));
  g_assert(LASSO_IS_SAML_CONDITION_ABSTRACT(condition));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(condition), TRUE);
}

/**
 * lasso_saml_conditions_add_audienceRestrictionCondition:
 * @node: the <saml:Conditions> node object
 * @audienceRestrictionCondition: 
 * 
 * 
 **/
void
lasso_saml_conditions_add_audienceRestrictionCondition(LassoSamlConditions *node,
						       LassoSamlAudienceRestrictionCondition *audienceRestrictionCondition)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_CONDITIONS(node));
  g_assert(LASSO_IS_SAML_AUDIENCE_RESTRICTION_CONDITION(audienceRestrictionCondition));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(audienceRestrictionCondition), TRUE);
}

/**
 * lasso_saml_conditions_set_notBefore:
 * @node: the <saml:Conditions> node object
 * @notBefore: the value of "NotBefore" attribute
 * 
 * Sets the "NotBefore" attribute.
 *
 * Specifies the earliest time instant at which the assertion is valid. The
 * time value is encoded in UTC as described in Section 1.2.2
 * (oasis-sstc-saml-core-1.0.pdf).
 **/
void
lasso_saml_conditions_set_notBefore(LassoSamlConditions *node,
				    const xmlChar *notBefore)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_CONDITIONS(node));
  g_assert(notBefore != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "NotBefore", notBefore);
}

/**
 * lasso_saml_conditions_set_notOnOrAfter:
 * @node: the <saml:Conditions> node object
 * @notOnOrAfter: the value of "NotOnOrAfter" attribute.
 * 
 * Sets the "NotOnOrAfter" attribute.
 *
 * Specifies the time instant at which the assertion has expired. The time
 * value is encoded in UTC as described in Section 1.2.2
 * (oasis-sstc-saml-core-1.0.pdf).
 **/
void
lasso_saml_conditions_set_notOnOrAfter(LassoSamlConditions *node,
				       const xmlChar *notOnOrAfter)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_CONDITIONS(node));
  g_assert(notOnOrAfter != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "NotOnOrAfter", notOnOrAfter);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_conditions_instance_init(LassoSamlConditions *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlAssertionHRef,
		lassoSamlAssertionPrefix);
  class->set_name(LASSO_NODE(node), "Conditions");
}

static void
lasso_saml_conditions_class_init(LassoSamlConditionsClass *klass)
{
}

GType lasso_saml_conditions_get_type()
{
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlConditionsClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_conditions_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlConditions),
      0,
      (GInstanceInitFunc) lasso_saml_conditions_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlConditions",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_conditions_new:
 * 
 * Creates a new <saml:Conditions> node object.
 *
 * Return value: the new @LassoSamlConditions
 **/
LassoNode* lasso_saml_conditions_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_CONDITIONS, NULL));
}
