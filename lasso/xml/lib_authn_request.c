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

#include <lasso/xml/lib_authn_request.h>

/*
The <AuthnRequest> is defined as an extension of samlp:RequestAbstractType.
The RequestID attribute in samlp:RequestAbstractType has uniqueness
requirements placed on it by [SAMLCore11], which require it to have the
properties of a nonce.

Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthnRequest" type="AuthnRequestType" />
<xs:complexType name="AuthnRequestType">
  <xs:complexContent>
    <xs:extension base="samlp:RequestAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="AffiliationID" minOccurs="0"/>
        <xs:element ref="NameIDPolicy" minOccurs="0"/>
        <xs:element name="ForceAuthn" type="xs:boolean" minOccurs="0"/>
        <xs:element name="IsPassive" type="xs:boolean "minOccurs="0"/>
        <xs:element ref="ProtocolProfile" minOccurs="0"/>
        <xs:element name="AssertionConsumerServiceID" type="xs:string" minOccurs="0"/>
        <xs:element ref="RequestAuthnContext" minOccurs="0"/>
        <xs:element ref="RelayState" minOccurs="0"/>
        <xs:element ref="Scoping" minOccurs="0 "/>
      </xs:sequence>
      <xs:attribute ref="consent" use="optional"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

<xs:element name="ProviderID" type="md:entityIDType"/>
<xs:element name="AffiliationID" type="md:entityIDType"/>

From liberty-metadata-v1.0.xsd:
<xs:simpleType name="entityIDType">
  <xs:restriction base="xs:anyURI">
    <xs:maxLength value="1024" id="maxlengthid"/>
  </xs:restriction>
</xs:simpleType>

<xs:element name="NameIDPolicy" type="NameIDPolicyType"/>
<xs:simpleType name="NameIDPolicyType">
  <xs:restriction base="xs:string">
    <xs:enumeration value="none"/>
    <xs:enumeration value="onetime"/>
    <xs:enumeration value="federated"/>
    <xs:enumeration value="any"/ >
  </xs:restriction>
</xs:simpleType>

<xs:element name="ProtocolProfile" type="xs:anyURI"/>
<xs:element name="RelayState" type="xs:string"/>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_authn_request_set_affiliationID(LassoLibAuthnRequest *node,
					  const xmlChar *affiliationID) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(affiliationID != NULL);
  // FIXME : affiliationID lenght SHOULD be <= 1024

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AffiliationID", affiliationID, FALSE);
}

void
lasso_lib_authn_request_set_assertionConsumerServiceID(LassoLibAuthnRequest *node,
						       const xmlChar *assertionConsumerServiceID) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(assertionConsumerServiceID != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AssertionConsumerServiceID",
		   assertionConsumerServiceID, FALSE);
}

void
lasso_lib_authn_request_set_consent(LassoLibAuthnRequest *node,
				    const xmlChar *consent)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(consent != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "consent", consent);
}

void
lasso_lib_authn_request_set_forceAuthn(LassoLibAuthnRequest *node,
				       gint forceAuthn) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(forceAuthn == 0 || forceAuthn == 1);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  if (forceAuthn == 0) {
    class->new_child(LASSO_NODE (node), "ForceAuthn", "false", FALSE);
  }
  if (forceAuthn == 1) {
    class->new_child(LASSO_NODE (node), "ForceAuthn", "true", FALSE);
  }
}

void
lasso_lib_authn_request_set_isPassive(LassoLibAuthnRequest *node,
				      gint isPassive) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(isPassive == 0 || isPassive == 1);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  if (isPassive == 0) {
    class->new_child(LASSO_NODE (node), "IsPassive", "false", FALSE);
  }
  if (isPassive == 1) {
    class->new_child(LASSO_NODE (node), "IsPassive", "true", FALSE);
  }
}

/**
 * lasso_lib_authn_request_set_nameIDPolicy:
 * @node:         the pointer to <lib:AuthnRequest> node
 * @nameIDPolicy: the value of "NameIDPolicy" attribut.
 * 
 * Sets the "NameIDPolicy" attribut. It's an enumeration permitting requester
 * influence over name identifier policy at the identity provider.
 **/
void
lasso_lib_authn_request_set_nameIDPolicy(LassoLibAuthnRequest *node,
					 const xmlChar   *nameIDPolicy)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(nameIDPolicy != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "NameIDPolicy", nameIDPolicy, FALSE);
}

void
lasso_lib_authn_request_set_protocolProfile(LassoLibAuthnRequest *node,
					    const xmlChar *protocolProfile)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(protocolProfile != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProtocolProfile", protocolProfile, FALSE);
}

void
lasso_lib_authn_request_set_providerID(LassoLibAuthnRequest *node,
				       const xmlChar *providerID)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(providerID != NULL);
  // FIXME : providerID lenght SHOULD be <= 1024

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

void
lasso_lib_authn_request_set_relayState(LassoLibAuthnRequest *node,
				       const xmlChar *relayState) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(relayState != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "RelayState", relayState, FALSE);
}

void
lasso_lib_authn_request_set_requestAuthnContext(LassoLibAuthnRequest *node,
						LassoLibRequestAuthnContext *requestAuthnContext) {
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(LASSO_IS_LIB_REQUEST_AUTHN_CONTEXT(requestAuthnContext));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node),
		   LASSO_NODE (requestAuthnContext),
		   FALSE);
}

/**
 * lasso_lib_authn_request_set_scoping:
 * @node: the pointer to <lib:AuthnRequest/> node object
 * @scoping: the pointer to <lib:Scoping/> node object
 * 
 * Sets the "Scoping" element.
 **/
void
lasso_lib_authn_request_set_scoping(LassoLibAuthnRequest *node,
				    LassoLibScoping *scoping)
{
  g_assert(LASSO_IS_LIB_AUTHN_REQUEST(node));
  g_assert(LASSO_IS_LIB_SCOPING(scoping));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node),
		   LASSO_NODE (scoping),
		   FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_authn_request_instance_init(LassoLibAuthnRequest *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "AuthnRequest");
}

static void
lasso_lib_authn_request_class_init(LassoLibAuthnRequestClass *klass)
{
}

GType lasso_lib_authn_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibAuthnRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_authn_request_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAuthnRequest),
      0,
      (GInstanceInitFunc) lasso_lib_authn_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				       "LassoLibAuthnRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_authn_request_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST,
				 NULL));
}
