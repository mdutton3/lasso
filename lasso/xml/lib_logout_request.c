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

#include <lasso/xml/lib_logout_request.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="LogoutRequest" type="LogoutRequestType"/>
<xs:complexType name="LogoutRequestType">
  <xs:complexContent>
    <xs:extension base="samlp:RequestAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="saml:NameIdentifier"/>
        <xs:element name="SessionIndex" type="xs:string" minOccurs="0"/>
        <xs:element ref="RelayState" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute ref="consent" use="optional"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

<xs:element name="ProviderID" type="md:entityIDType"/>
<xs:element name="RelayState" type="xs:string"/>

From liberty-metadata-v1.0.xsd:
<xs:simpleType name="entityIDType">
  <xs:restriction base="xs:anyURI">
    <xs:maxLength value="1024" id="maxlengthid"/>
  </xs:restriction>
</xs:simpleType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/
void
lasso_lib_logout_request_set_consent(LassoLibLogoutRequest *node,
				     const xmlChar *consent)
{
  g_assert(LASSO_IS_LIB_LOGOUT_REQUEST(node));
  g_assert(consent != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "consent", consent);
}

void
lasso_lib_logout_request_set_nameIdentifier(LassoLibLogoutRequest *node,
					    LassoSamlNameIdentifier *nameIdentifier) {
  g_assert(LASSO_IS_LIB_LOGOUT_REQUEST(node));
  g_assert(LASSO_IS_SAML_NAME_IDENTIFIER(nameIdentifier));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE (nameIdentifier), FALSE);
}

void
lasso_lib_logout_request_set_providerID(LassoLibLogoutRequest *node,
					const xmlChar *providerID)
{
  g_assert(LASSO_IS_LIB_LOGOUT_REQUEST(node));
  g_assert(providerID != NULL);
  // FIXME : providerID lenght SHOULD be <= 1024

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

void
lasso_lib_logout_request_set_relayState(LassoLibLogoutRequest *node,
					const xmlChar *relayState) {
  g_assert(LASSO_IS_LIB_LOGOUT_REQUEST(node));
  g_assert(relayState != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "RelayState", relayState, FALSE);
}

void
lasso_lib_logout_request_set_sessionIndex(LassoLibLogoutRequest *node,
					  const xmlChar *sessionIndex) {
  g_assert(LASSO_IS_LIB_LOGOUT_REQUEST(node));
  g_assert(sessionIndex != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "SessionIndex", sessionIndex, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_logout_request_instance_init(LassoLibLogoutRequest *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "LogoutRequest");
}

static void
lasso_lib_logout_request_class_init(LassoLibLogoutRequestClass *klass)
{
}

GType lasso_lib_logout_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibLogoutRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_logout_request_class_init,
      NULL,
      NULL,
      sizeof(LassoLibLogoutRequest),
      0,
      (GInstanceInitFunc) lasso_lib_logout_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				       "LassoLibLogoutRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_logout_request_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST,
				 NULL));
}
