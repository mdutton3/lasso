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

#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

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

	/* signature stuff */
	if (response->sign_type != LASSO_SIGNATURE_TYPE_NONE) {
		xmlDoc *doc;
		xmlNode *signature = NULL, *reference, *key_info;
		char *uri;

		if (response->sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1) {
			signature = xmlSecTmplSignatureCreate(NULL, xmlSecTransformExclC14NId,
					xmlSecTransformRsaSha1Id, NULL);
		}
		if (response->sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
			signature = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
					xmlSecTransformDsaSha1Id, NULL);
		}
		/* get out if signature == NULL ? */
		xmlAddChild(xmlnode, signature);

		uri = g_strdup_printf("#%s", response->ResponseID);
		reference = xmlSecTmplSignatureAddReference(signature,
				xmlSecTransformSha1Id, NULL, uri, NULL);
		g_free(uri);

		/* add enveloped transform */
		xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
		/* add exclusive C14N transform */
		xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);

		/* add <dsig:KeyInfo/> */
		if (response->sign_type == LASSO_SIGNATURE_TYPE_WITHX509) {
			key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
			xmlSecTmplKeyInfoAddX509Data(key_info);
		}
	}


	return xmlnode;
} 

static gboolean
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

	if (response->ResponseID == NULL || response->IssueInstant == NULL ||
			response->MajorVersion == 0)
		return FALSE;
	
	return TRUE;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	char *t;
	LassoSamlpResponseAbstract *response = LASSO_SAMLP_RESPONSE_ABSTRACT(node);

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

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
	return 0;
}

static char*
get_sign_attr_name()
{
	return "ResponseID";
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
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoSamlpResponseAbstractClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
	LASSO_NODE_CLASS(klass)->build_query = build_query;
  	LASSO_NODE_CLASS(klass)->init_from_query = init_from_query;
	LASSO_NODE_CLASS(klass)->get_sign_attr_name = get_sign_attr_name;
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

