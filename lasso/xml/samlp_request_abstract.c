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

#include <lasso/xml/samlp_request_abstract.h>

/*
 * Schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):
 * 
 * <complexType name="RequestAbstractType" abstract="true">
 *   <sequence>
 *     <element ref="samlp:RespondWith" minOccurs="0" maxOccurs="unbounded"/>
 *     <element ref="ds:Signature" minOccurs="0"/>
 *   </sequence>
 *   <attribute name="RequestID" type="saml:IDType" use="required"/>
 *   <attribute name="MajorVersion" type="integer" use="required"/>
 *   <attribute name="MinorVersion" type="integer" use="required"/>
 *   <attribute name="IssueInstant" type="dateTime" use="required"/>
 * </complexType>
 * 
 * <element name="RespondWith" type="QName"/>
 * 
 * From oasis-sstc-saml-schema-assertion-1.0.xsd:
 * <simpleType name="IDType">
 *   <restriction base="string"/>
 * </simpleType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "RequestID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlpRequestAbstract, RequestID) },
	{ "MajorVersion", SNIPPET_ATTRIBUTE_INT,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, MajorVersion) },
	{ "MinorVersion", SNIPPET_ATTRIBUTE_INT,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, MinorVersion) },
	{ "IssueInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, IssueInstant) },
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

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

	xmlnode = parent_class->get_xmlNode(node);

	/* signature stuff */
	if (request->sign_type != LASSO_SIGNATURE_TYPE_NONE) {
		xmlNode *signature = NULL, *reference, *key_info;
		char *uri;

		if (request->sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1) {
			signature = xmlSecTmplSignatureCreate(NULL, xmlSecTransformExclC14NId,
					xmlSecTransformRsaSha1Id, NULL);
		}
		if (request->sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
			signature = xmlSecTmplSignatureCreate(NULL, xmlSecTransformExclC14NId,
					xmlSecTransformDsaSha1Id, NULL);
		}
		/* get out if signature == NULL ? */
		xmlAddChild(xmlnode, signature);

		uri = g_strdup_printf("#%s", request->RequestID);
		reference = xmlSecTmplSignatureAddReference(signature,
				xmlSecTransformSha1Id, NULL, uri, NULL);
		g_free(uri);

		/* add enveloped transform */
		xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
		/* add exclusive C14N transform */
		xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);

		/* add <dsig:KeyInfo/> */
		if (request->sign_type == LASSO_SIGNATURE_TYPE_WITHX509) {
			key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
			xmlSecTmplKeyInfoAddX509Data(key_info);
		}
	}

	return xmlnode;
} 

static gboolean
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

	if (request->RequestID == NULL || request->IssueInstant == NULL ||
			request->MajorVersion == 0)
		return FALSE;
	
	return TRUE;
}

static char*
get_sign_attr_name()
{
	return "RequestID";
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
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoSamlpRequestAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_query = init_from_query;
	nclass->get_sign_attr_name = get_sign_attr_name;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RequestAbstract");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
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
	return g_object_new(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT, NULL);
}

