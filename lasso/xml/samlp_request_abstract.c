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

#include <lasso/xml/samlp_request_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<complexType name="RequestAbstractType" abstract="true">
  <sequence>
    <element ref="samlp:RespondWith" minOccurs="0" maxOccurs="unbounded"/>
    <element ref="ds:Signature" minOccurs="0"/>
  </sequence>
  <attribute name="RequestID" type="saml:IDType" use="required"/>
  <attribute name="MajorVersion" type="integer" use="required"/>
  <attribute name="MinorVersion" type="integer" use="required"/>
  <attribute name="IssueInstant" type="dateTime" use="required"/>
</complexType>

<element name="RespondWith" type="QName"/>

From oasis-sstc-saml-schema-assertion-1.0.xsd:
<simpleType name="IDType">
  <restriction base="string"/>
</simpleType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_samlp_request_abstract_add_respondWith(LassoSamlpRequestAbstract *node,
					     const xmlChar *respondWith)
{
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(respondWith != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "RespondWith", respondWith, TRUE);
}

void
lasso_samlp_request_abstract_set_issueInstance(LassoSamlpRequestAbstract *node,
					       const xmlChar *issueInstance) {
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(issueInstance != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "IssueInstance", issueInstance);
}

void
lasso_samlp_request_abstract_set_majorVersion(LassoSamlpRequestAbstract *node,
					      const xmlChar *majorVersion) {
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(majorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MajorVersion", majorVersion);
}

void
lasso_samlp_request_abstract_set_minorVersion(LassoSamlpRequestAbstract *node,
					      const xmlChar *minorVersion) {
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(minorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MinorVersion", minorVersion);
}

/**
 * lasso_samlp_request_abstract_impl_set_requestID:
 * @node: the pointer to <Samlp:RequestAbstract/> node
 * @requestID: the RequestID attribut
 * 
 * Sets the RequestID attribut (unique)
 **/
void
lasso_samlp_request_abstract_set_requestID(LassoSamlpRequestAbstract *node,
					   const xmlChar *requestID)
{
  g_assert(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node));
  g_assert(requestID != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "RequestID", requestID);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_samlp_request_abstract_instance_init(LassoSamlpRequestAbstract *instance,
					   LassoSamlpRequestAbstractClass *klass) {
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, NULL, "samlp");
  class->set_name(node, "RequestAbstract");
}

static void
lasso_samlp_request_abstract_class_init(LassoSamlpRequestAbstractClass *klass)
{
}

GType lasso_samlp_request_abstract_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlpRequestAbstractClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_samlp_request_abstract_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlpRequestAbstract),
      0,
      (GInstanceInitFunc) lasso_samlp_request_abstract_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE ,
				       "LassoSamlpRequestAbstract",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_samlp_request_abstract_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				 NULL));
}
