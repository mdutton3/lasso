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

#include <lasso/xml/samlp_response_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<complexType name="ResponseAbstractType" abstract="true">
  <sequence>
     <element ref="ds:Signature" minOccurs="0"/>
  </sequence>
  <attribute name="ResponseID" type="saml:IDType" use="required"/>
  <attribute name="InResponseTo" type="saml:IDReferenceType" use="optional"/>
  <attribute name="MajorVersion" type="integer" use="required"/>
  <attribute name="MinorVersion" type="integer" use="required"/>
  <attribute name="IssueInstant" type="dateTime" use="required"/>
  <attribute name="Recipient" type="anyURI" use="optional"/>
</complexType>

From oasis-sstc-saml-schema-assertion-1.0.xsd:
<simpleType name="IDType">
  <restriction base="string"/>
</simpleType>
<simpleType name="IDReferenceType">
  <restriction base="string"/>
</simpleType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

#if 0
gint
lasso_samlp_response_abstract_set_signature(LassoSamlpResponseAbstract *node,
		gint                        sign_method,
		const xmlChar              *private_key_file,
		const xmlChar              *certificate_file)
{
	return 0;
}

gint
lasso_samlp_response_abstract_set_signature_tmpl(LassoSamlpResponseAbstract *node,
		lassoSignatureType sign_type,
		lassoSignatureMethod sign_method)
{
	LassoNodeClass *class;

	return 0; /* FIXME: signature disabled for now */

	g_return_val_if_fail(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	class = LASSO_NODE_GET_CLASS(node);

	return class->add_signature_tmpl(LASSO_NODE (node), sign_type, sign_method, NULL);
}

gint
lasso_samlp_response_abstract_sign_signature_tmpl(LassoSamlpResponseAbstract *node,
		const xmlChar *private_key_file, const xmlChar *certificate_file)
{
	LassoNodeClass *class;

	return 0; /* FIXME: signature disabled for now */

	g_return_val_if_fail(LASSO_IS_SAMLP_RESPONSE_ABSTRACT(node),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	class = LASSO_NODE_GET_CLASS(node);

	return class->sign_signature_tmpl(LASSO_NODE (node), private_key_file,
			certificate_file);
}
#endif

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static gchar*
build_query(LassoNode *node)
{
	char *str;

	str = g_strdup_printf("ResponseID=%s&MajorVersion=%d&MinorVersion=%d&IssueInstant=%s",
			LASSO_SAMLP_RESPONSE_ABSTRACT(node)->ResponseID,
			LASSO_SAMLP_RESPONSE_ABSTRACT(node)->MajorVersion,
			LASSO_SAMLP_RESPONSE_ABSTRACT(node)->MinorVersion,
			LASSO_SAMLP_RESPONSE_ABSTRACT(node)->IssueInstant);
	/* XXX: & Recipient & InResponseTo*/
	return str;
}


static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	LassoSamlpResponseAbstract *response = LASSO_SAMLP_RESPONSE_ABSTRACT(node);
	char t[10];

	xmlnode = xmlNewNode(NULL, "ResponseAbstract");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX));
	xmlSetProp(xmlnode, "ResponseID", response->ResponseID);
	snprintf(t, 9, "%d", response->MajorVersion);
	xmlSetProp(xmlnode, "MajorVersion", t);
	snprintf(t, 9, "%d", response->MinorVersion);
	xmlSetProp(xmlnode, "MinorVersion", t);
	xmlSetProp(xmlnode, "IssueInstant", response->IssueInstant);
	if (response->InResponseTo)
		xmlSetProp(xmlnode, "InResponseTo", t);
	if (response->Recipient)
		xmlSetProp(xmlnode, "Recipient", t);

	return xmlnode;
} 

static void
init_from_query(LassoNode *node, char **query_fields)
{
	LassoSamlpResponseAbstract *response = LASSO_SAMLP_RESPONSE_ABSTRACT(node);
	int i;
	char *t;

	for (i=0; (t=query_fields[i]); i++) {
		if (strncmp(t, "ResponseID=", 10) == 0) {
			response->ResponseID = g_strdup(t+10);
			continue;
		}
		if (strncmp(t, "MajorVersion=", 13) == 0) {
			response->MajorVersion = atoi(t+13);
			continue;
		}
		if (strncmp(t, "MinorVersion=", 13) == 0) {
			response->MinorVersion = atoi(t+13);
			continue;
		}
		if (strncmp(t, "IssueInstant=", 13) == 0) {
			response->IssueInstant = g_strdup(t+13);
			continue;
		}
		if (strncmp(t, "Recipient=", 9) == 0) {
			response->Recipient = g_strdup(t+9);
			continue;
		}
		if (strncmp(t, "InResponseTo=", 13) == 0) {
			response->InResponseTo = g_strdup(t+13);
			continue;
		}
	}
	parent_class->init_from_query(node, query_fields);
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	char *t;
	LassoSamlpResponseAbstract *response = LASSO_SAMLP_RESPONSE_ABSTRACT(node);

	parent_class->init_from_xml(node, xmlnode);

	response->ResponseID = xmlGetProp(xmlnode, "ResponseID");
	response->IssueInstant = xmlGetProp(xmlnode, "IssueInstant");
	response->InResponseTo = xmlGetProp(xmlnode, "InResponseTo");
	response->Recipient = xmlGetProp(xmlnode, "Recipient");
	t = xmlGetProp(xmlnode, "MajorVersion");
	if (t) {
		response->MajorVersion = atoi(t);
		xmlFree(t);
	}
	t = xmlGetProp(xmlnode, "MinorVersion");
	if (t) {
		response->MinorVersion = atoi(t);
		xmlFree(t);
	}
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlpResponseAbstract *node)
{
	node->ResponseID = NULL;
	node->MajorVersion = 0;
	node->MinorVersion = 0;
	node->IssueInstant = NULL;
	node->InResponseTo = NULL;
	node->Recipient = NULL;
}

static void
class_init(LassoSamlpResponseAbstractClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
  	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
}

GType
lasso_samlp_response_abstract_get_type()
{
	static GType response_abstract_type = 0;

	if (!response_abstract_type) {
		static const GTypeInfo response_abstract_info = {
			sizeof (LassoSamlpResponseAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpResponseAbstract),
			0,
			(GInstanceInitFunc) instance_init,
		};

		response_abstract_type = g_type_register_static(LASSO_TYPE_NODE ,
				"LassoSamlpResponseAbstract",
				&response_abstract_info, 0);
	}
	return response_abstract_type;
}

void
lasso_samlp_response_abstract_fill(LassoSamlpResponseAbstract *response,
		const char *InResponseTo, const char *Recipient)
{
	response->ResponseID = lasso_build_unique_id(32);
	response->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	response->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	response->IssueInstant = lasso_get_current_time();
	response->InResponseTo = g_strdup(InResponseTo);
	response->Recipient = g_strdup(Recipient);
}

LassoNode*
lasso_samlp_response_abstract_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT, NULL);
}

