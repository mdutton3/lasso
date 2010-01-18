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
#include "lib_authn_response.h"

/**
 * SECTION:lib_authn_response
 * @short_description: &lt;lib:AuthnResponse&gt;
 *
 * <figure><title>Schema fragment for lib:AuthnResponse</title>
 * <programlisting><![CDATA[
 * <xs:element name="AuthnResponse" type="AuthnResponseType"/>
 * <xs:complexType name="AuthnResponseType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:ResponseType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 * 	<xs:element ref="ProviderID"/>
 * 	<xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 *
 * <xs:element name="ProviderID" type="md:entityIDType"/>
 * <xs:element name="RelayState" type="xs:string"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoLibAuthnResponse, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibAuthnResponse, ProviderID), NULL, NULL, NULL},
	{ "RelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibAuthnResponse, RelayState), NULL, NULL, NULL},
	{ "consent", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoLibAuthnResponse, consent), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibAuthnResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AuthnResponse");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_authn_response_get_type()
{
	static GType authn_response_type = 0;

	if (!authn_response_type) {
		static const GTypeInfo authn_response_info = {
			sizeof (LassoLibAuthnResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnResponse),
			0,
			NULL,
			NULL
		};

		authn_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE,
				"LassoLibAuthnResponse", &authn_response_info, 0);
	}
	return authn_response_type;
}


/**
 * lasso_lib_authn_response_new:
 * @providerID: the identity provider ID
 * @request: the #LassoLibAuthnRequest it is a response to
 *
 * Creates a new #LassoLibAuthnResponse object.
 *
 * Return value: a newly created #LassoLibAuthnResponse object
 **/
LassoNode*
lasso_lib_authn_response_new(char *providerID, LassoLibAuthnRequest *request)
{
	LassoLibAuthnResponse *response;

	response = g_object_new(LASSO_TYPE_LIB_AUTHN_RESPONSE, NULL);

	if (providerID) {
		lasso_samlp_response_abstract_fill(
				LASSO_SAMLP_RESPONSE_ABSTRACT(response),
				LASSO_SAMLP_REQUEST_ABSTRACT(request)->RequestID,
				request->ProviderID);
		response->ProviderID = g_strdup(providerID);
		response->RelayState = g_strdup(request->RelayState);
	}

	return LASSO_NODE(response);
}
