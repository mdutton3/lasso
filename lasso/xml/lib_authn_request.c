/* $id: lib_authn_request.c,v 1.18 2004/11/26 14:13:02 fpeters Exp $
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

#include "private.h"
#include "lib_authn_request.h"
#include <libxml/uri.h>
#include "../utils.h"

/**
 * SECTION:lib_authn_request
 * @short_description: &lt;lib:AuthnRequest&gt;
 * @see_also: #LassoLogin
 *
 * Authentication requests are sent from a service provider to an identity
 * provider.
 *
 * <blockquote>
 * The lib:AuthnRequest is defined as an extension of samlp:RequestAbstractType.
 * The RequestID attribute in samlp:RequestAbstractType has uniqueness
 * requirements placed on it by [SAMLCore11], which require it to have the
 * properties of a nonce.
 * </blockquote>
 *
 * <figure><title>Schema fragment for lib:AuthnRequest</title>
 * <programlisting><![CDATA[
 * <xs:element name="AuthnRequest" type="AuthnRequestType" />
 * <xs:complexType name="AuthnRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="AffiliationID" minOccurs="0"/>
 *         <xs:element ref="NameIDPolicy" minOccurs="0"/>
 *         <xs:element name="ForceAuthn" type="xs:boolean" minOccurs="0"/>
 *         <xs:element name="IsPassive" type="xs:boolean "minOccurs="0"/>
 *         <xs:element ref="ProtocolProfile" minOccurs="0"/>
 *         <xs:element name="AssertionConsumerServiceID" type="xs:string" minOccurs="0"/>
 *         <xs:element ref="RequestAuthnContext" minOccurs="0"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *         <xs:element ref="Scoping" minOccurs="0 "/>
 *       </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 *
 * <xs:element name="ProviderID" type="md:entityIDType"/>
 * <xs:element name="AffiliationID" type="md:entityIDType"/>
 *
 * <xs:element name="NameIDPolicy" type="NameIDPolicyType"/>
 * <xs:simpleType name="NameIDPolicyType">
 *   <xs:restriction base="xs:string">
 *     <xs:enumeration value="none"/>
 *     <xs:enumeration value="onetime"/>
 *     <xs:enumeration value="federated"/>
 *     <xs:enumeration value="any"/ >
 *   </xs:restriction>
 * </xs:simpleType>
 *
 * <xs:element name="ProtocolProfile" type="xs:anyURI"/>
 * <xs:element name="RelayState" type="xs:string"/>
 * ]]></programlisting>
 * </figure>
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoLibAuthnRequest, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibAuthnRequest, ProviderID), NULL, NULL, NULL},
	{ "AffiliationID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibAuthnRequest, AffiliationID), NULL, NULL, NULL},
	{ "NameIDPolicy", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibAuthnRequest, NameIDPolicy), NULL, NULL, NULL},
	{ "ForceAuthn", SNIPPET_CONTENT | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoLibAuthnRequest, ForceAuthn), NULL, NULL, NULL},
	{ "IsPassive", SNIPPET_CONTENT | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoLibAuthnRequest, IsPassive), NULL, NULL, NULL},
	{ "ProtocolProfile", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnRequest, ProtocolProfile), NULL, NULL, NULL},
	{ "AssertionConsumerServiceID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnRequest, AssertionConsumerServiceID), NULL, NULL, NULL},
	{ "RequestAuthnContext", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibAuthnRequest, RequestAuthnContext), NULL, NULL, NULL},
	{ "RelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibAuthnRequest, RelayState), NULL, NULL, NULL},
	{ "Scoping", SNIPPET_NODE, G_STRUCT_OFFSET(LassoLibAuthnRequest, Scoping), NULL, NULL, NULL},
	{ "consent", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoLibAuthnRequest, consent), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static struct QuerySnippet query_snippets[] = {
	{ "RequestID", NULL },
	{ "MajorVersion", NULL },
	{ "MinorVersion", NULL },
	{ "IssueInstant", NULL },
	{ "ProviderID", NULL },
	{ "AffiliationID", NULL },
	{ "ForceAuthn", NULL },
	{ "IsPassive", NULL },
	{ "NameIDPolicy", NULL },
	{ "ProtocolProfile", NULL },
	{ "AssertionConsumerServiceID", NULL },
	{ "RequestAuthnContext/AuthnContextStatementRef", "AuthnContextStatementRef" },
	{ "RequestAuthnContext/AuthnContextClassRef", "AuthnContextClassRef" },
	{ "RequestAuthnContext/AuthnContextComparison", "AuthnContextComparison" },
	{ "RelayState", NULL },
	{ "Scoping/ProxyCount", "ProxyCount" },
	{ "Scoping/IDPList/IDPEntries", "IDPEntries" },
	{ "Scoping/IDPList/GetComplete", "GetComplete" },
	{ "consent", NULL },
	{ "Extension", NULL },
	{ NULL, NULL }
};

static LassoNodeClass *parent_class = NULL;

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibAuthnRequest *request = LASSO_LIB_AUTHN_REQUEST(node);
	gboolean rc;

	request->RequestAuthnContext = lasso_lib_request_authn_context_new();
	/* XXX needs code for Scoping, IDPList, IDPEntries... */
	rc = parent_class->init_from_query(node, query_fields);

	if (request->RequestAuthnContext->AuthnContextClassRef == NULL &&
			request->RequestAuthnContext->AuthnContextStatementRef == NULL &&
			request->RequestAuthnContext->AuthnContextComparison == NULL) {
		lasso_release_gobject(request->RequestAuthnContext);
	}

	if (request->ProviderID == NULL)
		return FALSE;

	return rc;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAuthnRequest *node)
{
	node->IsPassive = TRUE;
}

static void
class_init(LassoLibAuthnRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnRequest");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	lasso_node_class_add_query_snippets(nclass, query_snippets);
}

GType
lasso_lib_authn_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthnRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnRequest),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibAuthnRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_authn_request_new:
 *
 * Creates a new #LassoLibAuthnRequest object.
 *
 * Return value: a newly created #LassoLibAuthnRequest object
 **/
LassoLibAuthnRequest*
lasso_lib_authn_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST, NULL);
}
