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

#include <lasso/xml/lib_status_response.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:complexType name="StatusResponseType">
  <xs:complexContent>
    <xs:extension base="samlp:ResponseAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="samlp:Status"/>
        <xs:element ref="RelayState" minOccurs="0"/>
      </xs:sequence>
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
lasso_lib_status_response_set_providerID(LassoLibStatusResponse *node,
					 const xmlChar *providerID)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_STATUS_RESPONSE(node));
  g_assert(providerID != NULL);
  /* FIXME : providerID length SHOULD be <= 1024 */

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

void
lasso_lib_status_response_set_relayState(LassoLibStatusResponse *node,
					 const xmlChar *relayState)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_STATUS_RESPONSE(node));
  g_assert(relayState != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "RelayState", relayState, FALSE);
}

void
lasso_lib_status_response_set_status(LassoLibStatusResponse *node,
				     LassoSamlpStatus *status)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_STATUS_RESPONSE(node));
  g_assert(LASSO_IS_SAMLP_STATUS(status));
  
  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE (status), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_status_response_instance_init(LassoLibStatusResponse *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "StatusResponse");
}

static void
lasso_lib_status_response_class_init(LassoLibStatusResponseClass *klass)
{
}

GType lasso_lib_status_response_get_type() {
  static GType status_response_type = 0;

  if (!status_response_type) {
    static const GTypeInfo status_response_info = {
      sizeof (LassoLibStatusResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_status_response_class_init,
      NULL,
      NULL,
      sizeof(LassoLibStatusResponse),
      0,
      (GInstanceInitFunc) lasso_lib_status_response_instance_init,
    };
    
    status_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
						 "LassoLibStatusResponse",
						 &status_response_info, 0);
  }
  return status_response_type;
}

LassoNode* lasso_lib_status_response_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_STATUS_RESPONSE, NULL));
}
