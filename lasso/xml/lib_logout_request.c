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

#include <libxml/uri.h>
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
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	LassoLibLogoutRequest *request = LASSO_LIB_LOGOUT_REQUEST(node);
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "LogoutRequest");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));
	if (request->Extension)
		xmlNewTextChild(xmlnode, NULL, "Extension", request->Extension);
	if (request->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", request->ProviderID);
	if (request->NameIdentifier)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(request->NameIdentifier)));
	if (request->SessionIndex)
		xmlNewTextChild(xmlnode, NULL, "SessionIndex", request->SessionIndex);
	if (request->RelayState)
		xmlNewTextChild(xmlnode, NULL, "RelayState", request->RelayState);
	if (request->consent)
		xmlSetProp(xmlnode, "consent", request->consent);

	return xmlnode;
}

static gchar*
build_query(LassoNode *node)
{
	char *str, *t;
	GString *s;
	LassoLibLogoutRequest *request = LASSO_LIB_LOGOUT_REQUEST(node);

	str = parent_class->build_query(node);
	s = g_string_new(str);
	g_free(str);

	/* XXX Extension */

	if (request->ProviderID) {
		t = xmlURIEscapeStr(request->ProviderID, NULL);
		g_string_append_printf(s, "&ProviderID=%s", t);
		xmlFree(t);
	}
	if (request->NameIdentifier) {
		t = lasso_node_build_query(LASSO_NODE(request->NameIdentifier));
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->SessionIndex)
		g_string_append_printf(s, "&SessionIndex=%s", request->SessionIndex);
	if (request->RelayState)
		g_string_append_printf(s, "&RelayState=%s", request->RelayState);
	if (request->consent)
		g_string_append_printf(s, "&consent=%s", request->consent);

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

static void
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibLogoutRequest *request = LASSO_LIB_LOGOUT_REQUEST(node);
	int i;
	char *t;

	request->NameIdentifier = lasso_saml_name_identifier_new();
	
	for (i=0; (t=query_fields[i]); i++) {
		if (g_str_has_prefix(t, "ProviderID=")) {
			request->ProviderID = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "SessionIndex=")) {
			request->SessionIndex = g_strdup(t+16);
			continue;
		}
		if (g_str_has_prefix(t, "RelayState=")) {
			request->RelayState = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "consent=")) {
			request->consent = g_strdup(t+8);
			continue;
		}
		if (g_str_has_prefix(t, "NameIdentifier=")) {
			request->NameIdentifier->content = g_strdup(t+15);
			continue;
		}
		if (g_str_has_prefix(t, "NameFormat=")) {
			request->NameIdentifier->Format = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "NameQualifier=")) {
			request->NameIdentifier->NameQualifier = g_strdup(t+14);
			continue;
		}
	}
	parent_class->init_from_query(node, query_fields);
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibLogoutRequest *request = LASSO_LIB_LOGOUT_REQUEST(node);
	xmlNode *t, *n;

	parent_class->init_from_xml(node, xmlnode);

	t = xmlnode->children;
	while (t) {
		n = t;
		t = t->next;
		if (n->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (strcmp(n->name, "ProviderID") == 0) {
			request->ProviderID = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "NameIdentifier") == 0) {
			request->NameIdentifier = LASSO_SAML_NAME_IDENTIFIER(
					lasso_node_new_from_xmlNode(n));
			continue;
		}
		if (strcmp(n->name, "SessionIndex") == 0) {
			request->SessionIndex = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "RelayState") == 0) {
			request->RelayState = xmlNodeGetContent(n);
			continue;
		}
	}
	request->consent = xmlGetProp(xmlnode, "consent");
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibLogoutRequest *node)
{
	node->Extension = NULL;
	node->ProviderID = NULL;
	node->NameIdentifier = NULL;
	node->SessionIndex = NULL;
	node->RelayState = NULL;
	node->consent = NULL;
}

static void
class_init(LassoLibLogoutRequestClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
}

GType
lasso_lib_logout_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibLogoutRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibLogoutRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibLogoutRequest", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_logout_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST, NULL);
}

LassoNode*
lasso_lib_logout_request_new_full(char *providerID, LassoSamlNameIdentifier *nameIdentifier,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();
	request->sign_type = sign_type;
	request->sign_method = sign_method;
	LASSO_LIB_LOGOUT_REQUEST(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_LOGOUT_REQUEST(request)->NameIdentifier = g_object_ref(nameIdentifier);

	return LASSO_NODE(request);
}

