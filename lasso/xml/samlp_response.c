/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
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

#include <lasso/xml/samlp_response.h>

/*
Schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<element name="Response" type="samlp:ResponseType"/>
<complexType name="ResponseType">
  <complexContent>
    <extension base="samlp:ResponseAbstractType">
      <sequence>
        <element ref="samlp:Status"/>
        <element ref="saml:Assertion" minOccurs="0" maxOccurs="unbounded"/>
      </sequence>
    </extension>
  </complexContent>
</complexType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_samlp_response_add_assertion(LassoSamlpResponse *node,
				   gpointer assertion)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE(node));
  //g_assert(LASSO_IS_SAML_ASSERTION(assertion));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(assertion), TRUE);
}

void
lasso_samlp_response_set_status(LassoSamlpResponse *node,
				LassoSamlpStatus *status)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE(node));
  g_assert(LASSO_IS_SAMLP_STATUS(status));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(status), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_samlp_response_instance_init(LassoSamlpResponse *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  /* namespace herited from samlp:ResponseAbstract */
  class->set_name(LASSO_NODE(node), "Response");
}

static void
lasso_samlp_response_class_init(LassoSamlpResponseClass *klass) {
}

GType lasso_samlp_response_get_type() {
  static GType response_type = 0;

  if (!response_type) {
    static const GTypeInfo response_info = {
      sizeof (LassoSamlpResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_samlp_response_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlpResponse),
      0,
      (GInstanceInitFunc) lasso_samlp_response_instance_init,
    };
    
    response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT ,
					   "LassoSamlpResponse",
					   &response_info, 0);
  }
  return response_type;
}

LassoNode* lasso_samlp_response_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAMLP_RESPONSE, NULL));
}
