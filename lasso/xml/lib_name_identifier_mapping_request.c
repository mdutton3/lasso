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
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibNameIdentifierMappingRequest *request;
	
	request = LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "NameIdentifierMappingRequest");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (request->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", request->ProviderID);

	if (request->NameIdentifier)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(request->NameIdentifier)));

	if (request->TargetNamespace)
		xmlNewTextChild(xmlnode, NULL, "TargetNamespace", request->TargetNamespace);

	if (request->consent)
		xmlSetProp(xmlnode, "consent", request->consent);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibNameIdentifierMappingRequest *request = 
		LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(node);
	struct XmlSnippet snippets[] = {
		{ "ProviderID", 'c', (void**)&(request->ProviderID) },
		{ "NameIdentifier", 'n', (void**)&(request->NameIdentifier) },
		{ "TargetNamespace", 'c', (void**)&(request->TargetNamespace) },
		{ NULL, 0, NULL}
	};

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	request->consent = xmlGetProp(xmlnode, "consent");
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibNameIdentifierMappingRequest *node)
{
	node->Extension = NULL;
	node->ProviderID = NULL;
	node->NameIdentifier = NULL;
	node->TargetNamespace = NULL;
	node->consent = NULL;
}

static void
class_init(LassoLibNameIdentifierMappingRequestClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_name_identifier_mapping_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibNameIdentifierMappingRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibNameIdentifierMappingRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibNameIdentifierMappingRequest", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_name_identifier_mapping_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, NULL);
}

LassoNode*
lasso_lib_name_identifier_mapping_request_new_full(char *providerID,
		LassoSamlNameIdentifier *nameIdentifier, const char *targetNamespace,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();

	/* set the signature template */
	if (sign_type != LASSO_SIGNATURE_TYPE_NONE) {
#if 0 /* XXX: signatures are done differently */
		lasso_samlp_request_abstract_set_signature_tmpl(
				request, sign_type, sign_method, NULL);
#endif
	}

	/* ProviderID */
	LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request)->NameIdentifier = 
		g_object_ref(nameIdentifier);

	LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request)->TargetNamespace =
		g_strdup(targetNamespace);

	/* XXX: consent ?  */

	return LASSO_NODE(request);
}

