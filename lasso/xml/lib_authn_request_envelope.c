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

#include <lasso/xml/lib_authn_request_envelope.h>

/*     <xs:element name="AuthnRequestEnvelope" type="AuthnRequestEnvelopeType"/> */
/*     <xs:complexType name="AuthnRequestEnvelopeType"> */
/*         <xs:complexContent> */
/*             <xs:extension base="RequestEnvelopeType"> */
/*                 <xs:sequence> */
/*                     <xs:element ref="AuthnRequest"/> */
/*                     <xs:element ref="ProviderID"/> */
/*                     <xs:element name="ProviderName" type="xs:string" minOccurs="0"/> */
/*                     <xs:element name="AssertionConsumerServiceURL" type="xs:anyURI"/> */
/*                     <xs:element ref="IDPList" minOccurs="0"/> */
/*                     <xs:element name="IsPassive" type="xs:boolean" minOccurs="0"/> */
/*                 </xs:sequence> */
/*             </xs:extension> */
/*         </xs:complexContent> */
/*     </xs:complexType> */
/*     <xs:complexType name="RequestEnvelopeType"> */
/*         <xs:sequence> */
/*             <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
/*         </xs:sequence> */
/*     </xs:complexType> */
/*     <xs:element name="IDPList" type="IDPListType"/> */
/*     <xs:complexType name="IDPListType"> */
/*         <xs:sequence> */
/*             <xs:element ref="IDPEntries"/> */
/*             <xs:element ref="GetComplete" minOccurs="0"/> */
/*         </xs:sequence> */
/*     </xs:complexType> */
/*     <xs:complexType name="ResponseEnvelopeType"> */
/*         <xs:sequence> */
/*             <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
/*         </xs:sequence> */


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_authn_request_envelope_set_extension(LassoLibAuthnRequestEnvelope *node,
					       LassoNode                    *extension)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(LASSO_IS_NODE(extension));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE(node), extension, FALSE);
}

void lasso_lib_authn_request_envelope_set_authnRequest(LassoLibAuthnRequestEnvelope *node,
						       LassoLibAuthnRequest         *request)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(request));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE(node), LASSO_NODE(request), FALSE);
}

void
lasso_lib_authn_request_envelope_set_assertionConsumerServiceURL(LassoLibAuthnRequestEnvelope *node,
								 const xmlChar                *assertionConsumerServiceURL)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(assertionConsumerServiceURL != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE(node), "AssertionConsumerServiceURL", assertionConsumerServiceURL, FALSE);
}

void
lasso_lib_authn_request_envelope_set_providerID(LassoLibAuthnRequestEnvelope *node,
						const xmlChar                *providerID)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(providerID != NULL);
  /* FIXME : providerID lenght SHOULD be <= 1024 */

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE(node), "ProviderID", providerID, FALSE);
}

void lasso_lib_authn_request_envelope_set_providerName(LassoLibAuthnRequestEnvelope *node,
						       const xmlChar                *providerName)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(providerName != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE(node), "ProviderName", providerName, FALSE);
}

void lasso_lib_authn_request_envelope_set_idpList(LassoLibAuthnRequestEnvelope *node,
						  LassoLibIDPList              *idpList)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(LASSO_IS_LIB_IDP_LIST(idpList));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE(node), LASSO_NODE(idpList), FALSE);
}

void
lasso_lib_authn_request_envelope_set_isPassive(LassoLibAuthnRequestEnvelope *node,
					       gboolean                      isPassive) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(node));
  g_assert(isPassive == FALSE || isPassive == TRUE);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  if (isPassive == FALSE) {
    class->new_child(LASSO_NODE (node), "IsPassive", "false", FALSE);
  }
  if (isPassive == TRUE) {
    class->new_child(LASSO_NODE (node), "IsPassive", "true", FALSE);
  }
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_authn_request_envelope_instance_init(LassoLibAuthnRequestEnvelope *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "AuthnRequestEnvelope");
}

static void
lasso_lib_authn_request_envelope_class_init(LassoLibAuthnRequestEnvelopeClass *class)
{
}

GType lasso_lib_authn_request_envelope_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibAuthnRequestEnvelopeClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_authn_request_envelope_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAuthnRequestEnvelope),
      0,
      (GInstanceInitFunc) lasso_lib_authn_request_envelope_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibAuthnRequestEnvelope",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_authn_request_envelope_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE,
				 NULL));
}
