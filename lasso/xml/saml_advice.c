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

#include <lasso/xml/saml_advice.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="Advice" type="saml:AdviceType"/>
<complexType name="AdviceType">
  <choice minOccurs="0" maxOccurs="unbounded">
    <element ref="saml:AssertionIDReference"/>
    <element ref="saml:Assertion"/>
    <any namespace="##other" processContents="lax"/>
  </choice>
</complexType>

<element name="AssertionIDReference" type="saml:IDReferenceType"/>
<simpleType name="IDReferenceType">
  <restriction base="string"/>
</simpleType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_advice_add_assertionIDReference(LassoSamlAdvice *node,
					   const xmlChar *assertionIDReference)
{
  g_assert(LASSO_IS_SAML_ADVICE(node));
  g_assert(assertionIDReference != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node),
		   "AssertionIDReference",
		   assertionIDReference,
		   TRUE);
}

void
lasso_saml_advice_add_assertion(LassoSamlAdvice *node,
				gpointer *assertion)
{
  g_assert(LASSO_IS_SAML_ADVICE(node));
  //g_assert(LASSO_IS_SAML_ASSERTION(assertion));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE (assertion), TRUE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_advice_instance_init(LassoSamlAdvice *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlAssertionHRef,
		lassoSamlAssertionPrefix);
  class->set_name(LASSO_NODE(node), "Advice");
}

static void
lasso_saml_advice_class_init(LassoSamlAdviceClass *klass) {
}

GType lasso_saml_advice_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlAdviceClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_advice_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlAdvice),
      0,
      (GInstanceInitFunc) lasso_saml_advice_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlAdvice",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_advice_new:
 * 
 * Creates a new <saml:Advice> node object.
 *
 * The <Advice> element contains any additional information that the issuer
 * wishes to provide. This information MAY be ignored by applications without
 * affecting either the semantics or the validity of the assertion.
 * The <Advice> element contains a mixture of zero or more <Assertion>
 * elements, <AssertionIDReference> elements and elements in other namespaces,
 * with lax schema validation in effect for these other elements.
 * Following are some potential uses of the <Advice> element:
 *
 * - Include evidence supporting the assertion claims to be cited, either
 * directly (through incorporating the claims) or indirectly (by reference to
 * the supporting assertions).
 *
 * - State a proof of the assertion claims.
 *
 * - Specify the timing and distribution points for updates to the assertion.
 * 
 * Return value: the new @LassoSamlAdvice
 **/
LassoNode* lasso_saml_advice_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_ADVICE, NULL));
}
