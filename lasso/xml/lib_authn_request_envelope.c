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

/*
 * Schema:
 *
 * <xs:element name="AuthnRequestEnvelope" type="AuthnRequestEnvelopeType"/>
 * <xs:complexType name="AuthnRequestEnvelopeType">
 *   <xs:complexContent>
 *     <xs:extension base="RequestEnvelopeType">
 *       <xs:sequence>
 *         <xs:element ref="AuthnRequest"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element name="ProviderName" type="xs:string" minOccurs="0"/>
 *         <xs:element name="AssertionConsumerServiceURL" type="xs:anyURI"/>
 *         <xs:element ref="IDPList" minOccurs="0"/>
 *         <xs:element name="IsPassive" type="xs:boolean" minOccurs="0"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * <xs:complexType name="RequestEnvelopeType">
 *   <xs:sequence>
 *     <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 * <xs:element name="IDPList" type="IDPListType"/>
 * <xs:complexType name="IDPListType">
 *   <xs:sequence>
 *     <xs:element ref="IDPEntries"/>
 *     <xs:element ref="GetComplete" minOccurs="0"/>
 *   </xs:sequence>
 * </xs:complexType>
 * <xs:complexType name="ResponseEnvelopeType">
 *   <xs:sequence>
 *     <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoLibAuthnRequestEnvelope *env = LASSO_LIB_AUTHN_REQUEST_ENVELOPE(node); \
	char *is_passive = NULL; \
	struct XmlSnippet snippets[] = { \
		/* XXX: Extension */ \
		{ "ProviderID", 'c', (void**)&(env->ProviderID) }, \
		{ "ProviderName", 'c', (void**)&(env->ProviderName) }, \
		{ "AssertionConsumerServiceURL", 'c', \
			(void**)&(env->AssertionConsumerServiceURL) }, \
		{ "IDPList", 'n', (void**)&(env->IDPList) }, \
		{ "IsPassive", 'c', (void**)&is_passive }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "AuthnRequestEnvelope");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));
	is_passive = env->IsPassive ? "true" : "false";
	lasso_node_build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	if (is_passive) {
		env->IsPassive = (strcmp(is_passive, "true") == 0);
		xmlFree(is_passive);
	}
	return 0;
}

		
/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAuthnRequestEnvelope *node)
{
	node->Extension = NULL;
	node->AuthnRequest = NULL;
	node->ProviderID = NULL;
	node->ProviderName = NULL;
	node->AssertionConsumerServiceURL = NULL;
	node->IDPList = NULL;
	node->IsPassive = FALSE;
}

static void
class_init(LassoLibAuthnRequestEnvelopeClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_authn_request_envelope_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthnRequestEnvelopeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnRequestEnvelope),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibAuthnRequestEnvelope", &this_info, 0);
	}
	return this_type;
}

LassoLibAuthnRequestEnvelope*
lasso_lib_authn_request_envelope_new()
{
	return g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, NULL);
}

LassoLibAuthnRequestEnvelope*
lasso_lib_authn_request_envelope_new_full(LassoLibAuthnRequest *authnRequest,
		char *providerID, char *assertionConsumerServiceURL)
{
	LassoLibAuthnRequestEnvelope *request;

	request = g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, NULL);
	request->AuthnRequest = g_object_ref(authnRequest);
	request->ProviderID = g_strdup(providerID);
	request->AssertionConsumerServiceURL = g_strdup(assertionConsumerServiceURL);

	return request;
}

