/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/saml_audience_restriction_condition.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="AudienceRestrictionCondition" type="saml:AudienceRestrictionConditionType"/>
<complexType name="AudienceRestrictionConditionType">
  <complexContent>
    <extension base="saml:ConditionAbstractType">
      <sequence>
        <element ref="saml:Audience" maxOccurs="unbounded"/>
      </sequence>
    </extension>
  </complexContent>
</complexType>

<element name="Audience" type="anyURI"/>
*/

/*****************************************************************************/
/* publics methods                                                           */
/*****************************************************************************/

/**
 * lasso_saml_audience_restriction_condition_add_audience:
 * @node: the <saml:AudienceRestrictionCondition> node object
 * @audience: the value of "Audience" element
 * 
 * Adds an "Audience" element.
 *
 * A URI reference that identifies an intended audience. The URI reference MAY
 * identify a document that describes the terms and conditions of audience
 * membership.
 **/
void
lasso_saml_audience_restriction_condition_add_audience(LassoSamlAudienceRestrictionCondition *node,
						       const xmlChar *audience)
{
  g_assert(LASSO_IS_SAML_AUDIENCE_RESTRICTION_CONDITION(node));
  g_assert(audience != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "Audience", audience, TRUE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_audience_restriction_condition_instance_init(LassoSamlAudienceRestrictionCondition *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  /* namespace herited from saml:ConditionAbstract */
  class->set_name(LASSO_NODE(node), "AudienceRestrictionCondition");
}

static void
lasso_saml_audience_restriction_condition_class_init(LassoSamlAudienceRestrictionConditionClass *klass)
{
}

GType lasso_saml_audience_restriction_condition_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlAudienceRestrictionConditionClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_audience_restriction_condition_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlAudienceRestrictionCondition),
      0,
      (GInstanceInitFunc) lasso_saml_audience_restriction_condition_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAML_CONDITION_ABSTRACT,
				       "LassoSamlAudienceRestrictionCondition",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_audience_restriction_condition_new:
 * 
 * Creates a new <saml:AudienceRestrictionCondition> node object.
 * 
 * The <AudienceRestrictionCondition> element specifies that the assertion is
 * addressed to one or more specific audiences identified by <Audience>
 * elements. Although a party that is outside the audiences specified is
 * capable of drawing conclusions from an assertion, the issuer explicitly
 * makes no representation as to accuracy or trustworthiness to such a party.
 *
 * The AudienceRestrictionCondition evaluates to Valid if and only if the
 * relying party is a member of one or more of the audiences specified. The
 * issuer of an assertion cannot prevent a party to whom it is disclosed from
 * making a decision on the basis of the information provided. However, the
 * <AudienceRestrictionCondition> element allows the issuer to state explicitly
 * that no warranty is provided to such a party in a machine- and
 * human-readable form. While there can be no guarantee that a court would
 * uphold such a warranty exclusion in every circumstance, the probability of
 * upholding the warranty exclusion is considerably improved.
 *
 * Return value: the new @LassoSamlAudienceRestrictionCondition
 **/
LassoNode* lasso_saml_audience_restriction_condition_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION, NULL));
}
