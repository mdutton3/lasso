/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
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

#include <lasso/xml/samlp_response_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<complexType name="ResponseAbstractType" abstract="true">
  <sequence>
     <element ref="ds:Signature" minOccurs="0"/>
  </sequence>
  <attribute name="ResponseID" type="saml:IDType" use="required"/>
  <attribute name="InResponseTo" type="saml:IDReferenceType" use="optional"/>
  <attribute name="MajorVersion" type="integer" use="required"/>
  <attribute name="MinorVersion" type="integer" use="required"/>
  <attribute name="IssueInstant" type="dateTime" use="required"/>
  <attribute name="Recipient" type="anyURI" use="optional"/>
</complexType>

From oasis-sstc-saml-schema-assertion-1.0.xsd:
<simpleType name="IDType">
  <restriction base="string"/>
</simpleType>
<simpleType name="IDReferenceType">
  <restriction base="string"/>
</simpleType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_samlp_response_abstract_set_inResponseTo(LassoSamlpResponseAbstract *node,
					       const xmlChar *inResponseTo)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(inResponseTo != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "InResponseTo", inResponseTo);
}

void
lasso_samlp_response_abstract_set_issueInstance(LassoSamlpResponseAbstract *node,
						const xmlChar *issueInstance)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(issueInstance != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "IssueInstance", issueInstance);
}

void
lasso_samlp_response_abstract_set_majorVersion(LassoSamlpResponseAbstract *node,
					       const xmlChar *majorVersion)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(majorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MajorVersion", majorVersion);
}

void
lasso_samlp_response_abstract_set_minorVersion(LassoSamlpResponseAbstract *node,
					       const xmlChar *minorVersion)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(minorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MinorVersion", minorVersion);
}

void
lasso_samlp_response_abstract_set_recipient(LassoSamlpResponseAbstract *node,
					    const xmlChar *recipient)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(recipient != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "Recipient", recipient);
}

/**
 * lasso_samlp_response_abstract_set_responseId:
 * @node: the pointer to <Samlp:ResponseAbstract/> node
 * @responseId: the ResponseID attribute
 * 
 * Sets the ResponseID attribute (unique)
 **/
void
lasso_samlp_response_abstract_set_responseID(LassoSamlpResponseAbstract *node,
					     const xmlChar *responseID)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(responseID != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "ResponseID", responseID);
}

void
lasso_samlp_response_abstract_set_signature(LassoSamlpResponseAbstract *node,
					    gint                       sign_method,
					    const xmlChar             *private_key_file,
					    const xmlChar             *certificate_file)
{
  g_assert(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node));
  g_assert(private_key_file != NULL);
  g_assert(certificate_file != NULL);
  
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_signature(LASSO_NODE (node), sign_method,
		       private_key_file, certificate_file);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_samlp_response_abstract_instance_init(LassoSamlpResponseAbstract *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlProtocolHRef,
		lassoSamlProtocolPrefix);
  class->set_name(LASSO_NODE(node), "ResponseAbstract");
}

static void
lasso_samlp_response_abstract_class_init(LassoSamlpResponseAbstractClass *klass)
{
}

GType lasso_samlp_response_abstract_get_type() {
  static GType response_abstract_type = 0;

  if (!response_abstract_type) {
    static const GTypeInfo response_abstract_info = {
      sizeof (LassoSamlpResponseAbstractClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_samlp_response_abstract_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlpResponseAbstract),
      0,
      (GInstanceInitFunc) lasso_samlp_response_abstract_instance_init,
    };
    
    response_abstract_type = g_type_register_static(LASSO_TYPE_NODE ,
						    "LassoSamlpResponseAbstract",
						    &response_abstract_info, 0);
  }
  return response_abstract_type;
}

LassoNode* lasso_samlp_response_abstract_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT, NULL));
}
