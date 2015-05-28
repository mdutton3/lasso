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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "../private.h"
#include "samlp2_authn_request.h"

/**
 * SECTION:samlp2_authn_request
 * @short_description: &lt;samlp2:AuthnRequest&gt;
 *
 * <figure><title>Schema fragment for samlp2:AuthnRequest</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Subject", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, Subject), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "NameIDPolicy", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, NameIDPolicy), NULL, NULL, NULL},
	{ "Conditions", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, Conditions), NULL,
		LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "RequestedAuthnContext", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, RequestedAuthnContext), NULL, NULL, NULL},
	{ "Scoping", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, Scoping), NULL, NULL, NULL},
	{ "ForceAuthn", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, ForceAuthn), NULL, NULL, NULL},
	{ "IsPassive", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, IsPassive), NULL, NULL, NULL},
	{ "ProtocolBinding", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, ProtocolBinding), NULL, NULL, NULL},
	{ "AssertionConsumerServiceIndex",
		SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, AssertionConsumerServiceIndex), NULL, NULL, NULL},
	{ "AssertionConsumerServiceURL", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, AssertionConsumerServiceURL), NULL, NULL, NULL},
	{ "AttributeConsumingServiceIndex",
		SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL_NEG,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, AttributeConsumingServiceIndex), NULL, NULL, NULL},
	{ "ProviderName", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2AuthnRequest, ProviderName), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlp2AuthnRequest *node)
{
	node->AssertionConsumerServiceIndex = -1;
	node->AttributeConsumingServiceIndex = -1;
}

static void
class_init(LassoSamlp2AuthnRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->node_data->keep_xmlnode = TRUE;
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
			NULL
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
