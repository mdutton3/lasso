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

#include <lasso/xml/lib_name_identifier_mapping_response.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="NameIdentifierMappingResponse" type="NameIdentifierMappingResponseType"/>
<xs:complexType name="NameIdentifierMappingResponseType">
  <xs:complexContent>
    <xs:extension base="samlp:ResponseAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="samlp:Status"/>
        <xs:element ref="saml:NameIdentifier" minOccurs="0"/>
      </xs:sequence>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibNameIdentifierMappingResponse *response;

	response = LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(node);
	
	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "NameIdentifierMappingResponse");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (response->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", response->ProviderID);
	if (response->Status)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(response->Status)));
	if (response->NameIdentifier)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(response->NameIdentifier)));

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibNameIdentifierMappingResponse *response;
	xmlNode *t;

	response = LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(node);

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "ProviderID") == 0) {
			response->ProviderID = xmlNodeGetContent(t);
		}
		if (strcmp(t->name, "Status") == 0) {
			response->Status = LASSO_SAMLP_STATUS(lasso_node_new_from_xmlNode(t));
		}
		if (strcmp(t->name, "NameIdentifier") == 0) {
			response->NameIdentifier = LASSO_SAML_NAME_IDENTIFIER(
					lasso_node_new_from_xmlNode(t));
		}
		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibNameIdentifierMappingResponse *node)
{
	node->Extension = NULL;
	node->ProviderID = NULL;
	node->Status = NULL;
	node->NameIdentifier = NULL;
}

static void
class_init(LassoLibNameIdentifierMappingResponseClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_name_identifier_mapping_response_get_type()
{
	static GType name_identifier_mapping_response_type = 0;

	if (!name_identifier_mapping_response_type) {
		static const GTypeInfo name_identifier_mapping_response_info = {
			sizeof (LassoLibNameIdentifierMappingResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibNameIdentifierMappingResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		name_identifier_mapping_response_type = g_type_register_static
			(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
			 "LassoLibNameIdentifierMappingResponse",
			 &name_identifier_mapping_response_info, 0);
	}
	return name_identifier_mapping_response_type;
}

LassoNode*
lasso_lib_name_identifier_mapping_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL);
}

LassoNode*
lasso_lib_name_identifier_mapping_response_new_full(char *providerID, const char *statusCodeValue,
		LassoLibNameIdentifierMappingRequest *request,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoLibNameIdentifierMappingResponse *response;

	response = g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL);
	lasso_samlp_response_abstract_fill(
			LASSO_SAMLP_RESPONSE_ABSTRACT(response),
			LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID,
			request->ProviderID);
#if 0 /* XXX: signature to do */
	/* set the signature template */
	if (sign_type != LASSO_SIGNATURE_TYPE_NONE) {
		lasso_samlp_response_abstract_set_signature_tmpl(response, sign_type, sign_method);
	}
#endif

	response->ProviderID = g_strdup(providerID);
	response->Status = lasso_samlp_status_new();
	response->Status->StatusCode = lasso_samlp_status_code_new();
	response->Status->StatusCode->Value = g_strdup(statusCodeValue);

	return LASSO_NODE(response);
}

