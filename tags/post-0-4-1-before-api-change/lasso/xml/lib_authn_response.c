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

#include <lasso/xml/lib_authn_response.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthnResponse" type="AuthnResponseType"/>
<xs:complexType name="AuthnResponseType">
  <xs:complexContent>
    <xs:extension base="samlp:ResponseType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
	<xs:element ref="ProviderID"/>
	<xs:element ref="RelayState" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute ref="consent" use="optional"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

<xs:element name="ProviderID" type="md:entityIDType"/>
From liberty-metadata-v1.0.xsd:
<xs:simpleType name="entityIDType">
  <xs:restriction base="xs:anyURI">
    <xs:maxLength value="1024" id="maxlengthid"/>
  </xs:restriction>
</xs:simpleType>
<xs:element name="RelayState" type="xs:string"/>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_authn_response_set_consent(LassoLibAuthnResponse *node,
				     const xmlChar *consent)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE(node));
  g_assert(consent != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "consent", consent);
}

void
lasso_lib_authn_response_set_providerID(LassoLibAuthnResponse *node,
					const xmlChar *providerID)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE(node));
  g_assert(providerID != NULL);
  /* FIXME : providerID length SHOULD be <= 1024 */

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

void
lasso_lib_authn_response_set_relayState(LassoLibAuthnResponse *node,
					const xmlChar *relayState)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE(node));
  g_assert(relayState != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "RelayState", relayState, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_authn_response_instance_init(LassoLibAuthnResponse *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "AuthnResponse");
}

static void
lasso_lib_authn_response_class_init(LassoLibAuthnResponseClass *klass)
{
}

GType lasso_lib_authn_response_get_type() {
  static GType authn_response_type = 0;

  if (!authn_response_type) {
    static const GTypeInfo authn_response_info = {
      sizeof (LassoLibAuthnResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_authn_response_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAuthnResponse),
      0,
      (GInstanceInitFunc) lasso_lib_authn_response_instance_init,
    };
    
    authn_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE,
						 "LassoLibAuthnResponse",
						 &authn_response_info, 0);
  }
  return authn_response_type;
}

LassoNode* lasso_lib_authn_response_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_AUTHN_RESPONSE, NULL));
}
