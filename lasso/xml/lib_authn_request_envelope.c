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

/*     <xs:element name="AuthnRequestEnvelope" type="AuthnRequestEnvelopeType"/> */
/*     <xs:complexType name="AuthnRequestEnvelopeType"> */
/*         <xs:complexContent> */
/*             <xs:extension base="RequestEnvelopeType"> */
/*                 <xs:sequence> */
/*                     <xs:element ref="AuthnRequest"/> */
/*                     <xs:element ref="ProviderID"/> */
/*                     <xs:element name="ProviderName" type="xs:string" minOccurs="0"/> */
/*                     <xs:element name="AssertionConsumerServiceURL" type="xs:anyURI"/> */
/*                     <xs:element ref="IDPList" minOccurs="0"/> */
/*                     <xs:element name="IsPassive" type="xs:boolean" minOccurs="0"/> */
/*                 </xs:sequence> */
/*             </xs:extension> */
/*         </xs:complexContent> */
/*     </xs:complexType> */
/*     <xs:complexType name="RequestEnvelopeType"> */
/*         <xs:sequence> */
/*             <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
/*         </xs:sequence> */
/*     </xs:complexType> */
/*     <xs:element name="IDPList" type="IDPListType"/> */
/*     <xs:complexType name="IDPListType"> */
/*         <xs:sequence> */
/*             <xs:element ref="IDPEntries"/> */
/*             <xs:element ref="GetComplete" minOccurs="0"/> */
/*         </xs:sequence> */
/*     </xs:complexType> */
/*     <xs:complexType name="ResponseEnvelopeType"> */
/*         <xs:sequence> */
/*             <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
/*         </xs:sequence> */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibAuthnRequestEnvelope *env = LASSO_LIB_AUTHN_REQUEST_ENVELOPE(node);

	xmlnode = xmlNewNode(NULL, "AuthnRequestEnvelope");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (env->Extension)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(env->Extension)));
	if (env->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", env->ProviderID);
	if (env->ProviderName)
		xmlNewTextChild(xmlnode, NULL, "ProviderName", env->ProviderName);
	if (env->AssertionConsumerServiceURL)
		xmlNewTextChild(xmlnode, NULL, "AssertionConsumerServiceURL",
				env->AssertionConsumerServiceURL);
	if (env->IDPList)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(env->IDPList)));

	xmlNewTextChild(xmlnode, NULL, "IsPassive", env->IsPassive ? "true" : "false");

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibAuthnRequestEnvelope *env = LASSO_LIB_AUTHN_REQUEST_ENVELOPE(node);
	xmlNode *t, *n;
	char *s;

	parent_class->init_from_xml(node, xmlnode);

	t = xmlnode->children;
	while (t) {
		n = t;
		t = t->next;
		if (n->type != XML_ELEMENT_NODE) {
			continue;
		}
		if (strcmp(n->name, "Extension") == 0) {
			/* XXX */
			continue;
		}
		if (strcmp(n->name, "ProviderID") == 0) {
			env->ProviderID = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "ProviderName") == 0) {
			env->ProviderName = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "AssertionConsumerServiceURL") == 0) {
			env->AssertionConsumerServiceURL = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "IDPList") == 0) {
			env->IDPList = LASSO_LIB_IDP_LIST(lasso_node_new_from_xmlNode(n));
			continue;
		}
	}

	s = xmlGetProp(xmlnode, "IsPassive");
	if (s) {
		env->IsPassive = (strcmp(s, "true") == 0);
		xmlFree(s);
	}
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

LassoNode*
lasso_lib_authn_request_envelope_new()
{
	return g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, NULL);
}
