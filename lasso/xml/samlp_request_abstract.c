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

#include "errors.h"

#include <lasso/xml/samlp_request_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<complexType name="RequestAbstractType" abstract="true">
  <sequence>
    <element ref="samlp:RespondWith" minOccurs="0" maxOccurs="unbounded"/>
    <element ref="ds:Signature" minOccurs="0"/>
  </sequence>
  <attribute name="RequestID" type="saml:IDType" use="required"/>
  <attribute name="MajorVersion" type="integer" use="required"/>
  <attribute name="MinorVersion" type="integer" use="required"/>
  <attribute name="IssueInstant" type="dateTime" use="required"/>
</complexType>

<element name="RespondWith" type="QName"/>

From oasis-sstc-saml-schema-assertion-1.0.xsd:
<simpleType name="IDType">
  <restriction base="string"/>
</simpleType>

*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

#if 0
gint
lasso_samlp_request_abstract_set_signature(LassoSamlpRequestAbstract *node,
		gint sign_method, const xmlChar *private_key_file, const xmlChar *certificate_file)
{
	return 0;
}

gint
lasso_samlp_request_abstract_set_signature_tmpl(LassoSamlpRequestAbstract *node,
		lassoSignatureType sign_type, lassoSignatureMethod sign_method,
		xmlChar *reference_id)
{
	LassoNodeClass *class;

	g_return_val_if_fail(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	class = LASSO_NODE_GET_CLASS(node);

	return class->add_signature_tmpl(LASSO_NODE (node), sign_type, sign_method, reference_id);
}

gint
lasso_samlp_request_abstract_sign_signature_tmpl(LassoSamlpRequestAbstract *node,
		const xmlChar *private_key_file, const xmlChar *certificate_file)
{
	LassoNodeClass *class;
	gint result;
	char t[10];

	return 0; /* FIXME (signature is broken) */

	g_return_val_if_fail(LASSO_IS_SAMLP_REQUEST_ABSTRACT(node),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	class = LASSO_NODE_GET_CLASS(node);
	
	result = class->sign_signature_tmpl(LASSO_NODE(node), private_key_file, certificate_file);
	return result;

}
#endif


static gchar*
build_query(LassoNode *node)
{
	char *str;

	str = g_strdup_printf("RequestID=%s&MajorVersion=%d&MinorVersion=%d&IssueInstant=%s",
			LASSO_SAMLP_REQUEST_ABSTRACT(node)->RequestID,
			LASSO_SAMLP_REQUEST_ABSTRACT(node)->MajorVersion,
			LASSO_SAMLP_REQUEST_ABSTRACT(node)->MinorVersion,
			LASSO_SAMLP_REQUEST_ABSTRACT(node)->IssueInstant);
	return str;
}


static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	LassoSamlpRequestAbstract *request = LASSO_SAMLP_REQUEST_ABSTRACT(node);
	char t[10];

	xmlnode = xmlNewNode(NULL, "RequestAbstract");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX));
	xmlSetProp(xmlnode, "RequestID", request->RequestID);
	snprintf(t, 9, "%d", request->MajorVersion);
	xmlSetProp(xmlnode, "MajorVersion", t);
	snprintf(t, 9, "%d", request->MinorVersion);
	xmlSetProp(xmlnode, "MinorVersion", t);
	xmlSetProp(xmlnode, "IssueInstant", request->IssueInstant);

	return xmlnode;
} 

static void
init_from_query(LassoNode *node, char **query_fields)
{
	LassoSamlpRequestAbstract *request = LASSO_SAMLP_REQUEST_ABSTRACT(node);
	int i;
	char *t;

	for (i=0; (t=query_fields[i]); i++) {
		if (strncmp(t, "RequestID=", 10) == 0) {
			request->RequestID = g_strdup(t+10);
			continue;
		}
		if (strncmp(t, "MajorVersion=", 13) == 0) {
			request->MajorVersion = atoi(t+13);
			continue;
		}
		if (strncmp(t, "MinorVersion=", 13) == 0) {
			request->MinorVersion = atoi(t+13);
			continue;
		}
		if (strncmp(t, "IssueInstant=", 13) == 0) {
			request->IssueInstant = g_strdup(t+13);
			continue;
		}
	}
	parent_class->init_from_query(node, query_fields);
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	char *t;
	LassoSamlpRequestAbstract *request = LASSO_SAMLP_REQUEST_ABSTRACT(node);

	parent_class->init_from_xml(node, xmlnode);

	request->RequestID = xmlGetProp(xmlnode, "RequestID");
	request->IssueInstant = xmlGetProp(xmlnode, "IssueInstant");
	t = xmlGetProp(xmlnode, "MajorVersion");
	if (t) {
		request->MajorVersion = atoi(t);
		xmlFree(t);
	}
	t = xmlGetProp(xmlnode, "MinorVersion");
	if (t) {
		request->MinorVersion = atoi(t);
		xmlFree(t);
	}
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlpRequestAbstract *node)
{
	node->RespondWith = NULL;
	node->RequestID = NULL;
	node->MajorVersion = 0;
	node->MinorVersion = 0;
	node->IssueInstant = NULL;
}

static void
class_init(LassoSamlpRequestAbstractClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->build_query = build_query;
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
  	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_samlp_request_abstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpRequestAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpRequestAbstract),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlpRequestAbstract", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_samlp_request_abstract_new()
{
	return LASSO_NODE(g_object_new(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT, NULL));
}
