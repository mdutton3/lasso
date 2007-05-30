/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: See AUTHORS file in top-level directory.
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

#include "samlp2_authn_request.h"

/*
 * Schema fragment (saml-schema-protocol-2.0.xsd):
 *
 * <complexType name="AuthnRequestType">
 *   <complexContent>
 *     <extension base="samlp:RequestAbstractType">
 *       <sequence>
 *         <element ref="saml:Subject" minOccurs="0"/>
 *         <element ref="samlp:NameIDPolicy" minOccurs="0"/>
 *         <element ref="saml:Conditions" minOccurs="0"/>
 *         <element ref="samlp:RequestedAuthnContext" minOccurs="0"/>
 *         <element ref="samlp:Scoping" minOccurs="0"/>
 *       </sequence>
 *       <attribute name="ForceAuthn" type="boolean" use="optional"/>
 *       <attribute name="IsPassive" type="boolean" use="optional"/>
 *       <attribute name="ProtocolBinding" type="anyURI" use="optional"/>
 *       <attribute name="AssertionConsumerServiceIndex" type="unsignedShort" use="optional"/>
 *       <attribute name="AssertionConsumerServiceURL" type="anyURI" use="optional"/>
 *       <attribute name="AttributeConsumingServiceIndex" type="unsignedShort" use="optional"/>
 *       <attribute name="ProviderName" type="string" use="optional"/>
 *     </extension>
 *   </complexContent>
 * </complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Subject", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, Subject) },
	{ "NameIDPolicy", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, NameIDPolicy) },
	{ "Conditions", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, Conditions) },
	{ "RequestedAuthnContext", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, RequestedAuthnContext) },
	{ "Scoping", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, Scoping) },
	{ "ForceAuthn", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, ForceAuthn) },
	{ "IsPassive", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, IsPassive) },
	{ "ProtocolBinding", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, ProtocolBinding) },
	{ "AssertionConsumerServiceIndex",
		SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, AssertionConsumerServiceIndex) },
	{ "AssertionConsumerServiceURL", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, AssertionConsumerServiceURL) },
	{ "AttributeConsumingServiceIndex",
		SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, AttributeConsumingServiceIndex) },
	{ "ProviderName", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, ProviderName) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


static gchar*
build_query(LassoNode *node)
{
	char *ret, *deflated_message;

	deflated_message = lasso_node_build_deflated_query(node);
	if (deflated_message == NULL) {
		return NULL;
	}
	ret = g_strdup_printf("SAMLRequest=%s", deflated_message);
	/* XXX: must support RelayState (which profiles?) */
	g_free(deflated_message);
	return ret;
}


static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	gboolean rc;
	char *relay_state = NULL;
	LassoSamlp2AuthnRequest *request = LASSO_SAMLP2_AUTHN_REQUEST(node);

	rc = lasso_node_init_from_saml2_query_fields(node, query_fields, &relay_state);
	if (rc && relay_state != NULL) {
		request->relayState = relay_state;
	}
	return rc;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlp2AuthnRequest *node)
{
	node->Subject = NULL;
	node->NameIDPolicy = NULL;
	node->Conditions = NULL;
	node->RequestedAuthnContext = NULL;
	node->Scoping = NULL;
	node->ForceAuthn = FALSE;
	node->IsPassive = FALSE;
	node->ProtocolBinding = NULL;
	node->AssertionConsumerServiceIndex = -1;
	node->AssertionConsumerServiceURL = NULL;
	node->AttributeConsumingServiceIndex = -1;
	node->ProviderName = NULL;
	node->relayState = NULL;
}

static void
class_init(LassoSamlp2AuthnRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnRequest"); 
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp2_authn_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2AuthnRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2AuthnRequest),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP2_REQUEST_ABSTRACT,
				"LassoSamlp2AuthnRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_authn_request_new:
 *
 * Creates a new #LassoSamlp2AuthnRequest object.
 *
 * Return value: a newly created #LassoSamlp2AuthnRequest object
 **/
LassoNode*
lasso_samlp2_authn_request_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_AUTHN_REQUEST, NULL);
}
