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

#include <lasso/xml/lib_name_identifier_mapping_request.h>

/*
The schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<xs:element name="NameIdentifierMappingRequest" type="NameIdentifierMappingRequestType"/>
<xs:complexType name="NameIdentifierMappingRequestType">
  <xs:complexContent>
    <xs:extension base="samlp:RequestAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="saml:NameIdentifier"/>
        <xs:element name="TargetNamespace" type="md:entityIDType"/>
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

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/
void
lasso_lib_name_identifier_mapping_request_set_consent(LassoLibNameIdentifierMappingRequest *node,
						      const xmlChar *consent)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(node));
  g_assert(consent != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "consent", consent);
}

void
lasso_lib_name_identifier_mapping_request_set_providerID(LassoLibNameIdentifierMappingRequest *node,
							 const xmlChar *providerID)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(node));
  g_assert(providerID != NULL);
  /* FIXME : providerId length SHOULD be <= 1024 */

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

void
lasso_lib_name_identifier_mapping_request_set_nameIdentifier(LassoLibNameIdentifierMappingRequest *node,
							     LassoSamlNameIdentifier *nameIdentifier)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(node));
  g_assert(LASSO_IS_SAML_NAME_IDENTIFIER(nameIdentifier));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE (nameIdentifier), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_name_identifier_mapping_request_instance_init(LassoLibNameIdentifierMappingRequest *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "NameIdentifierMappingRequest");
}

static void
lasso_lib_name_identifier_mapping_request_class_init(LassoLibNameIdentifierMappingRequestClass *klass)
{
}

GType lasso_lib_name_identifier_mapping_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibNameIdentifierMappingRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_name_identifier_mapping_request_class_init,
      NULL,
      NULL,
      sizeof(LassoLibNameIdentifierMappingRequest),
      0,
      (GInstanceInitFunc) lasso_lib_name_identifier_mapping_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				       "LassoLibNameIdentifierMappingRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_name_identifier_mapping_request_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST,
				 NULL));
}
