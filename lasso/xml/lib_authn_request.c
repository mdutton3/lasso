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

#include <lasso/xml/lib_authn_request.h>
#include <libxml/uri.h>

/*
 * The <AuthnRequest> is defined as an extension of samlp:RequestAbstractType.
 * The RequestID attribute in samlp:RequestAbstractType has uniqueness
 * requirements placed on it by [SAMLCore11], which require it to have the
 * properties of a nonce.
 * 
 * Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):
 * 
 * <xs:element name="AuthnRequest" type="AuthnRequestType" />
 * <xs:complexType name="AuthnRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 * 	<xs:element ref="AffiliationID" minOccurs="0"/>
 *         <xs:element ref="NameIDPolicy" minOccurs="0"/>
 *         <xs:element name="ForceAuthn" type="xs:boolean" minOccurs="0"/>
 *         <xs:element name="IsPassive" type="xs:boolean "minOccurs="0"/>
 *         <xs:element ref="ProtocolProfile" minOccurs="0"/>
 *         <xs:element name="AssertionConsumerServiceID" type="xs:string" minOccurs="0"/>
 *         <xs:element ref="RequestAuthnContext" minOccurs="0"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *         <xs:element ref="Scoping" minOccurs="0 "/>
 *       </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * 
 * <xs:element name="ProviderID" type="md:entityIDType"/>
 * <xs:element name="AffiliationID" type="md:entityIDType"/>
 * 
 * From liberty-metadata-v1.0.xsd:
 * <xs:simpleType name="entityIDType">
 *   <xs:restriction base="xs:anyURI">
 *     <xs:maxLength value="1024" id="maxlengthid"/>
 *   </xs:restriction>
 * </xs:simpleType>
 * 
 * <xs:element name="NameIDPolicy" type="NameIDPolicyType"/>
 * <xs:simpleType name="NameIDPolicyType">
 *   <xs:restriction base="xs:string">
 *     <xs:enumeration value="none"/>
 *     <xs:enumeration value="onetime"/>
 *     <xs:enumeration value="federated"/>
 *     <xs:enumeration value="any"/ >
 *   </xs:restriction>
 * </xs:simpleType>
 * 
 * <xs:element name="ProtocolProfile" type="xs:anyURI"/>
 * <xs:element name="RelayState" type="xs:string"/>
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoLibAuthnRequest *request = LASSO_LIB_AUTHN_REQUEST(node); \
	char *force_authn = NULL, *is_passive = NULL; \
	struct XmlSnippet snippets[] = { \
		{ "ProviderID", 'c', (void**)&(request->ProviderID) }, \
		{ "NameIDPolicy", 'c', (void**)&(request->NameIDPolicy) }, \
		{ "ProtocolProfile", 'c', (void**)&(request->ProtocolProfile) }, \
		{ "AssertionConsumerServiceID", 'c', \
			(void**)&(request->AssertionConsumerServiceID) }, \
		/* XXX: RequestAuthnContext */ \
		{ "RelayState", 'c', (void**)&(request->RelayState) }, \
		{ "ForceAuthn", 'c', (void**)&force_authn }, \
		{ "IsPassive", 'c', (void**)&is_passive }, \
		/* XXX: Scoping */ \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	is_passive = request->IsPassive ? "true" : "false";
	force_authn = request->ForceAuthn ? "true" : "false";

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "AuthnRequest");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));
	lasso_node_build_xml_with_snippets(xmlnode, snippets);
	if (request->consent)
		xmlSetProp(xmlnode, "consent", request->consent);

	return xmlnode;
}

static gchar*
build_query(LassoNode *node)
{
	char *str, *t;
	GString *s;
	LassoLibAuthnRequest *request = LASSO_LIB_AUTHN_REQUEST(node);

	str = parent_class->build_query(node);
	s = g_string_new(str);
	g_free(str);

	if (request->ProviderID) {
		t = xmlURIEscapeStr(request->ProviderID, NULL);
		g_string_append_printf(s, "&ProviderID=%s", t);
		xmlFree(t);
	}
	if (request->AffiliationID)
		g_string_append_printf(s, "&AffiliationID=%s", request->AffiliationID);
	if (request->NameIDPolicy)
		g_string_append_printf(s, "&NameIDPolicy=%s", request->NameIDPolicy);
	if (request->ProtocolProfile) {
		t = xmlURIEscapeStr(request->ProtocolProfile, NULL);
		g_string_append_printf(s, "&ProtocolProfile=%s", t);
		xmlFree(t);
	}
	if (request->RelayState)
		g_string_append_printf(s, "&RelayState=%s", request->RelayState);
	if (request->consent)
		g_string_append_printf(s, "&consent=%s", request->consent);
	g_string_append_printf(s, "&ForceAuthn=%s", request->ForceAuthn ? "true" : "false");
	g_string_append_printf(s, "&IsPassive=%s", request->IsPassive ? "true" : "false");

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibAuthnRequest *request = LASSO_LIB_AUTHN_REQUEST(node);
	int i;
	char *t;
	
	for (i=0; (t=query_fields[i]); i++) {
		if (strncmp(t, "ProviderID=", 11) == 0) {
			request->ProviderID = g_strdup(t+11);
			continue;
		}
		if (strncmp(t, "AffiliationID=", 14) == 0) {
			request->AffiliationID = g_strdup(t+14);
			continue;
		}
		if (strncmp(t, "NameIDPolicy=", 13) == 0) {
			request->NameIDPolicy = g_strdup(t+13);
			continue;
		}
		if (strncmp(t, "ProtocolProfile=", 16) == 0) {
			request->ProtocolProfile = g_strdup(t+16);
			continue;
		}
		if (strncmp(t, "RelayState=", 11) == 0) {
			request->RelayState = g_strdup(t+11);
			continue;
		}
		if (strncmp(t, "consent=", 8) == 0) {
			request->consent =g_strdup(t+8);
			continue;
		}
		if (strncmp(t, "ForceAuthn=", 11) == 0) {
			request->ForceAuthn = (strcmp(t+11, "true") == 0);
			continue;
		}
		if (strncmp(t, "IsPassive=", 10) == 0) {
			request->IsPassive = (strcmp(t+10, "true") == 0);
			continue;
		}
	}

	if (request->ProviderID == NULL)
		return FALSE;
	
	return parent_class->init_from_query(node, query_fields);
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();
	
	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	request->consent = xmlGetProp(xmlnode, "consent");
	lasso_node_init_xml_with_snippets(xmlnode, snippets);

	if (is_passive) {
		request->IsPassive = (strcmp(is_passive, "true") == 0);
		xmlFree(is_passive);
	}
	if (force_authn) {
		request->ForceAuthn = (strcmp(force_authn, "true") == 0);
		xmlFree(force_authn);
	}

	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAuthnRequest *node)
{
	node->ProviderID = NULL;
	node->AffiliationID = NULL;
	node->NameIDPolicy = NULL;
	node->ForceAuthn = FALSE;
	node->IsPassive = TRUE;
	node->ProtocolProfile = NULL;
	node->AssertionConsumerServiceID = NULL;
	node->RequestAuthnContext = NULL;
	node->RelayState = NULL;
	node->Scoping = NULL;
	node->consent = NULL;
}

static void
class_init(LassoLibAuthnRequestClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->build_query = build_query;
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_query = init_from_query;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_lib_authn_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthnRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibAuthnRequest", &this_info, 0);
	}
	return this_type;
}

LassoLibAuthnRequest*
lasso_lib_authn_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST, NULL);
}

