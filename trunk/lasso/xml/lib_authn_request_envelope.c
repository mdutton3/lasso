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

#include "private.h"
#include "lib_authn_request_envelope.h"

/**
 * SECTION:lib_authn_request_envelope
 * @short_description: &lt;lib:AuthnRequestEnvelope&gt;
 *
 * <figure><title>Schema fragment for lib:AuthnRequestEnvelope</title>
 * <programlisting><![CDATA[
 * <xs:element name="AuthnRequestEnvelope" type="AuthnRequestEnvelopeType"/>
 * <xs:complexType name="AuthnRequestEnvelopeType">
 *   <xs:complexContent>
 *     <xs:extension base="RequestEnvelopeType">
 *       <xs:sequence>
 *         <xs:element ref="AuthnRequest"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element name="ProviderName" type="xs:string" minOccurs="0"/>
 *         <xs:element name="AssertionConsumerServiceURL" type="xs:anyURI"/>
 *         <xs:element ref="IDPList" minOccurs="0"/>
 *         <xs:element name="IsPassive" type="xs:boolean" minOccurs="0"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * <xs:complexType name="RequestEnvelopeType">
 *   <xs:sequence>
 *     <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 * <xs:element name="IDPList" type="IDPListType"/>
 * <xs:complexType name="IDPListType">
 *   <xs:sequence>
 *     <xs:element ref="IDPEntries"/>
 *     <xs:element ref="GetComplete" minOccurs="0"/>
 *   </xs:sequence>
 * </xs:complexType>
 * <xs:complexType name="ResponseEnvelopeType">
 *   <xs:sequence>
 *     <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, Extension), NULL, NULL, NULL},
	{ "AuthnRequest", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, AuthnRequest), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, ProviderID), NULL, NULL, NULL},
	{ "ProviderName", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, ProviderName), NULL, NULL, NULL},
	{ "AssertionConsumerServiceURL", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, AssertionConsumerServiceURL), NULL, NULL, NULL},
	{ "IDPList", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, IDPList), NULL, NULL, NULL},
	{ "IsPassive", SNIPPET_CONTENT | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoLibAuthnRequestEnvelope, IsPassive), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibAuthnRequestEnvelopeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnRequestEnvelope");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
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
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibAuthnRequestEnvelope", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_lib_authn_request_envelope_new:
 *
 * Creates a new #LassoLibAuthnRequestEnvelope object.
 *
 * Return value: a newly created #LassoLibAuthnRequestEnvelope object
 **/
LassoLibAuthnRequestEnvelope*
lasso_lib_authn_request_envelope_new()
{
	return g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, NULL);
}


/**
 * lasso_lib_authn_request_envelope_new_full:
 * @authnRequest: the #LassoLibAuthnRequest to envelop
 * @providerID: service provider ID
 * @assertionConsumerServiceURL: assertion consumer service URL on the service
 *      provider
 *
 * Creates a new #LassoLibAuthnRequestEnvelope object and initializes it with
 * the parameters.
 *
 * Return value: a newly created #LassoLibAuthnRequestEnvelope object
 **/
LassoLibAuthnRequestEnvelope*
lasso_lib_authn_request_envelope_new_full(LassoLibAuthnRequest *authnRequest,
		char *providerID, char *assertionConsumerServiceURL)
{
	LassoLibAuthnRequestEnvelope *request;

	request = g_object_new(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, NULL);
	request->AuthnRequest = g_object_ref(authnRequest);
	request->ProviderID = g_strdup(providerID);
	request->AssertionConsumerServiceURL = g_strdup(assertionConsumerServiceURL);

	return request;
}
