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
#include <lasso/xml/lib_register_name_identifier_request.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="RegisterNameIdentifierRequest" type="RegisterNameIdentifierRequestType"/>
<xs:complexType name="RegisterNameIdentifierRequestType">
  <xs:complexContent>
    <xs:extension base="samlp:RequestAbstractType">
      <xs:sequence>
        <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element ref="ProviderID"/>
        <xs:element ref="IDPProvidedNameIdentifier"/>
        <xs:element ref="SPProvidedNameIdentifier" minOccurs="0"/>
        <xs:element ref="OldProvidedNameIdentifier"/>
        <xs:element ref="RelayState" minOccurs="0"/>
      </xs:sequence>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>
<xs:element name="IDPProvidedNameIdentifier" type="saml:NameIdentifierType"/>
<xs:element name="SPProvidedNameIdentifier" type="saml:NameIdentifierType"/>
<xs:element name="OldProvidedNameIdentifier" type="saml:NameIdentifierType"/>

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
	xmlNode *xmlnode, *t;
	LassoLibRegisterNameIdentifierRequest *request;
	xmlNs *xmlns;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "RegisterNameIdentifierRequest");
	xmlns = xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	xmlSetNs(xmlnode, xmlns);

	if (request->Extension)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(request->Extension));
	if (request->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", request->ProviderID);

	if (request->IDPProvidedNameIdentifier) {
		t = xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(request->IDPProvidedNameIdentifier)));
		xmlNodeSetName(t, "IDPProvidedNameIdentifier");
		xmlSetNs(t, xmlns);
	}

	if (request->SPProvidedNameIdentifier) {
		t = xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(request->SPProvidedNameIdentifier)));
		xmlNodeSetName(t, "SPProvidedNameIdentifier");
		xmlSetNs(t, xmlns);
	}

	if (request->OldProvidedNameIdentifier) {
		t = xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(request->OldProvidedNameIdentifier)));
		xmlNodeSetName(t, "OldProvidedNameIdentifier");
		xmlSetNs(t, xmlns);
	}
	if (request->RelayState)
		xmlNewTextChild(xmlnode, NULL, "RelayState", request->RelayState);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	xmlNode *t, *n;
	LassoLibRegisterNameIdentifierRequest *request;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	
	t = xmlnode->children;
	while (t) {
		n = t;
		t = t->next;
		if (n->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp(n->name, "ProviderID") == 0) {
			request->ProviderID = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "IDPProvidedNameIdentifier") == 0) {
			request->IDPProvidedNameIdentifier = 
				lasso_saml_name_identifier_new_from_xmlNode(n);
			continue;
		}
		if (strcmp(n->name, "SPProvidedNameIdentifier") == 0) {
			request->SPProvidedNameIdentifier = 
				lasso_saml_name_identifier_new_from_xmlNode(n);
			continue;
		}
		if (strcmp(n->name, "OldProvidedNameIdentifier") == 0) {
			request->OldProvidedNameIdentifier = 
				lasso_saml_name_identifier_new_from_xmlNode(n);
			continue;
		}
		if (strcmp(n->name, "RelayState") == 0) {
			request->RelayState = xmlNodeGetContent(n);
			continue;
		}
	}
	return 0;
}

static gchar*
build_query(LassoNode *node)
{
	char *str, *t;
	GString *s;
	LassoLibRegisterNameIdentifierRequest *request;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	str = parent_class->build_query(node);
	s = g_string_new(str);
	g_free(str);

	/* XXX Extension */

	if (request->ProviderID) {
		t = xmlURIEscapeStr(request->ProviderID, NULL);
		g_string_append_printf(s, "&ProviderID=%s", t);
		xmlFree(t);
	}
	if (request->IDPProvidedNameIdentifier) {
		t = lasso_saml_name_identifier_build_query(
				request->IDPProvidedNameIdentifier, "IDP", "IDPProvided");
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->SPProvidedNameIdentifier) {
		t = lasso_saml_name_identifier_build_query(
				request->SPProvidedNameIdentifier, "SP", "SPProvided");
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->OldProvidedNameIdentifier) {
		t = lasso_saml_name_identifier_build_query(
				request->OldProvidedNameIdentifier, "Old", "OldProvided");
		g_string_append_printf(s, "&%s", t);
		g_free(t);
	}
	if (request->RelayState)
		g_string_append_printf(s, "&RelayState=%s", request->RelayState);

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

static void
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibRegisterNameIdentifierRequest *request;
	int i;
	char *t;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	request->IDPProvidedNameIdentifier = lasso_saml_name_identifier_new();
	request->SPProvidedNameIdentifier = lasso_saml_name_identifier_new();
	request->OldProvidedNameIdentifier = lasso_saml_name_identifier_new();
	
	for (i=0; (t=query_fields[i]); i++) {
		if (g_str_has_prefix(t, "ProviderID=")) {
			request->ProviderID = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "RelayState=")) {
			request->RelayState = g_strdup(t+11);
			continue;
		}
		if (g_str_has_prefix(t, "IDPProvidedNameIdentifier=")) {
			request->IDPProvidedNameIdentifier->content = g_strdup(t+26);
			continue;
		}
		if (g_str_has_prefix(t, "IDPNameFormat=")) {
			request->IDPProvidedNameIdentifier->Format = g_strdup(t+14);
			continue;
		}
		if (g_str_has_prefix(t, "IDPNameQualifier=")) {
			request->IDPProvidedNameIdentifier->NameQualifier = g_strdup(t+17);
			continue;
		}
		if (g_str_has_prefix(t, "SPProvidedNameIdentifier=")) {
			request->SPProvidedNameIdentifier->content = g_strdup(t+25);
			continue;
		}
		if (g_str_has_prefix(t, "SPNameFormat=")) {
			request->SPProvidedNameIdentifier->Format = g_strdup(t+13);
			continue;
		}
		if (g_str_has_prefix(t, "SPNameQualifier=")) {
			request->SPProvidedNameIdentifier->NameQualifier = g_strdup(t+16);
			continue;
		}
		if (g_str_has_prefix(t, "OldProvidedNameIdentifier=")) {
			request->OldProvidedNameIdentifier->content = g_strdup(t+26);
			continue;
		}
		if (g_str_has_prefix(t, "OldNameFormat=")) {
			request->OldProvidedNameIdentifier->Format = g_strdup(t+14);
			continue;
		}
		if (g_str_has_prefix(t, "OldNameQualifier=")) {
			request->OldProvidedNameIdentifier->NameQualifier = g_strdup(t+17);
			continue;
		}
	}
	parent_class->init_from_query(node, query_fields);

	if (request->IDPProvidedNameIdentifier->content == NULL) {
		g_object_unref(request->IDPProvidedNameIdentifier);
		request->IDPProvidedNameIdentifier = NULL;
	}
	if (request->SPProvidedNameIdentifier->content == NULL) {
		g_object_unref(request->SPProvidedNameIdentifier);
		request->SPProvidedNameIdentifier = NULL;
	}
	if (request->OldProvidedNameIdentifier->content == NULL) {
		g_object_unref(request->OldProvidedNameIdentifier);
		request->OldProvidedNameIdentifier = NULL;
	}
}




/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibRegisterNameIdentifierRequest *node)
{
	node->ProviderID = NULL;
	node->IDPProvidedNameIdentifier = NULL;
	node->SPProvidedNameIdentifier = NULL;
	node->OldProvidedNameIdentifier = NULL;
	node->RelayState = NULL;
}

static void
class_init(LassoLibRegisterNameIdentifierRequestClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
}

GType
lasso_lib_register_name_identifier_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibRegisterNameIdentifierRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibRegisterNameIdentifierRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibRegisterNameIdentifierRequest", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_register_name_identifier_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, NULL);
}

LassoNode*
lasso_lib_register_name_identifier_request_new_full(char *providerID,
		LassoSamlNameIdentifier *idpNameIdentifier,
		LassoSamlNameIdentifier *spNameIdentifier,
		LassoSamlNameIdentifier *oldNameIdentifier)
{
	LassoLibRegisterNameIdentifierRequest *request;
	LassoSamlpRequestAbstract *request_base;

	request = g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, NULL);
	request_base = LASSO_SAMLP_REQUEST_ABSTRACT(request);

	request_base->RequestID = lasso_build_unique_id(32);
	request_base->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request_base->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request_base->IssueInstant = lasso_get_current_time();

	request->ProviderID = g_strdup(providerID);
	request->IDPProvidedNameIdentifier = idpNameIdentifier;
	request->SPProvidedNameIdentifier = spNameIdentifier;
	request->OldProvidedNameIdentifier = oldNameIdentifier;


	return LASSO_NODE(request);
}


