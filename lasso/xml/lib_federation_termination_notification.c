/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/xml/lib_federation_termination_notification.h>
#include <libxml/uri.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="FederationTerminationNotification" type="FederationTerminationNotificationType"/>
  <xs:complexType name="FederationTerminationNotificationType">
    <xs:complexContent>
      <xs:extension base="samlp:RequestAbstractType">
        <xs:sequence>
          <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
          <xs:element ref="ProviderID"/>
          <xs:element ref="saml:NameIdentifier"/>
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

#define snippets() \
	LassoLibFederationTerminationNotification *ob = \
		LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(node); \
	struct XmlSnippet snippets[] = { \
		{ "ProviderID", 'c', (void**)&(ob->ProviderID) }, \
		{ "NameIdentifier", 'n', (void**)&(ob->NameIdentifier) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "FederationTerminationNotification");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));
	lasso_node_build_xml_with_snippets(xmlnode, snippets);

	if (ob->consent)
		xmlSetProp(xmlnode, "consent", ob->consent);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode))
		return 1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	ob->consent = xmlGetProp(xmlnode, "consent");
	return 0;
}


static gchar*
build_query(LassoNode *node)
{
	char *str, *t;
	GString *s;
	LassoLibFederationTerminationNotification *request;
	
	request = LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(node);

	str = parent_class->build_query(node);
	s = g_string_new(str);
	g_free(str);

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
	if (request->consent)
		g_string_append_printf(s, "&consent=%s", request->consent);

	str = s->str;
	g_string_free(s, FALSE);

	return str;
}

static void
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibFederationTerminationNotification *request;
	int i;
	char *t;

	request = LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(node);

	request->NameIdentifier = lasso_saml_name_identifier_new();
	
	for (i=0; (t=query_fields[i]); i++) {
		if (g_str_has_prefix(t, "ProviderID=")) {
			request->ProviderID = g_strdup(t+11);
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




/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibFederationTerminationNotification *node)
{
	node->ProviderID = NULL;
	node->NameIdentifier = NULL;
	node->consent = NULL;
}

static void
class_init(LassoLibFederationTerminationNotificationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
}

GType
lasso_lib_federation_termination_notification_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibFederationTerminationNotificationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibFederationTerminationNotification),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibFederationTerminationNotification", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_federation_termination_notification_new()
{
	return g_object_new(LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION, NULL);
}

LassoNode*
lasso_lib_federation_termination_notification_new_full(char *providerID,
		LassoSamlNameIdentifier *nameIdentifier,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();

	/* set the signature template */
	if (sign_type != LASSO_SIGNATURE_TYPE_NONE) {
#if 0 /* XXX: signatures are done differently */
		lasso_samlp_request_abstract_set_signature_tmpl(request, sign_type, sign_method, NULL);
#endif
	}

	LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(request)->NameIdentifier =
		g_object_ref(nameIdentifier);

	return LASSO_NODE(request);
}

