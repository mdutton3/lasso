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
#include <libxml/uri.h>
#include "lib_logout_request.h"
#include "../utils.h"

/**
 * SECTION:lib_logout_request
 * @short_description: &lt;lib:LogoutRequest&gt;
 *
 * <figure><title>Schema fragment for lib:LogoutRequest</title>
 * <programlisting><![CDATA[
 * <xs:element name="LogoutRequest" type="LogoutRequestType"/>
 * <xs:complexType name="LogoutRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="saml:NameIdentifier"/>
 *         <xs:element name="SessionIndex" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
 *       <xs:attribute ref="consent" use="optional"/>
 *       <xs:attribute name="NotOnOrAfter" type="xs:dateTime" use="optional"/>
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
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoLibLogoutRequest, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibLogoutRequest, ProviderID), NULL, NULL, NULL},
	{ "NameIdentifier", SNIPPET_NODE, G_STRUCT_OFFSET(LassoLibLogoutRequest, NameIdentifier), NULL, NULL, NULL},
	{ "SessionIndex", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibLogoutRequest, SessionIndex), NULL, NULL, NULL},
	{ "RelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibLogoutRequest, RelayState), NULL, NULL, NULL},
	{ "consent", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoLibLogoutRequest, consent), NULL, NULL, NULL},
	{ "NotOnOrAfter", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibLogoutRequest, NotOnOrAfter), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static struct QuerySnippet query_snippets[] = {
	{ "RequestID", NULL },
	{ "MajorVersion", NULL },
	{ "MinorVersion", NULL },
	{ "IssueInstant", NULL },
	{ "ProviderID", NULL },
	{ "NameIdentifier/NameQualifier", "NameQualifier" },
	{ "NameIdentifier/Format", "NameFormat" },
	{ "NameIdentifier/content", "NameIdentifier" },
	{ "SessionIndex", NULL },
	{ "RelayState", NULL },
	{ "consent", NULL },
	{ NULL, NULL }
};


static LassoNodeClass *parent_class = NULL;

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibLogoutRequest *request = LASSO_LIB_LOGOUT_REQUEST(node);
	gboolean rc;

	request->NameIdentifier = lasso_saml_name_identifier_new();

	rc = parent_class->init_from_query(node, query_fields);
	if (! rc)
		goto cleanup;

	if (request->ProviderID == NULL ||
			request->NameIdentifier == NULL ||
			request->NameIdentifier->content == NULL) {
		lasso_release_gobject(request->NameIdentifier);
		return FALSE;
	}

	if (request->NameIdentifier->Format == NULL) {
		lasso_assign_string(request->NameIdentifier->Format,
				"LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED");
	}
cleanup:

	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibLogoutRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "LogoutRequest");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	lasso_node_class_add_query_snippets(nclass, query_snippets);
}

GType
lasso_lib_logout_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibLogoutRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibLogoutRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibLogoutRequest", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lib_logout_request_new:
 *
 * Creates a new #LassoLibLogoutRequest object.
 *
 * Return value: a newly created #LassoLibLogoutRequest object
 **/
LassoNode*
lasso_lib_logout_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST, NULL);
}


/**
 * lasso_lib_logout_request_new_full:
 * @providerID: the provider ID requesting the logout
 * @nameIdentifier: the name identifier to log out
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibLogoutRequest object and initializes it with the
 * parameters.
 *
 * Return value: a newly created #LassoLibLogoutRequest object
 **/
LassoNode*
lasso_lib_logout_request_new_full(char *providerID, LassoSamlNameIdentifier *nameIdentifier,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
{
	LassoSamlpRequestAbstract *request;

	request = g_object_new(LASSO_TYPE_LIB_LOGOUT_REQUEST, NULL);

	request->RequestID = lasso_build_unique_id(32);
	request->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request->IssueInstant = lasso_get_current_time();
	request->sign_type = sign_type;
	request->sign_method = sign_method;
	LASSO_LIB_LOGOUT_REQUEST(request)->ProviderID = g_strdup(providerID);
	LASSO_LIB_LOGOUT_REQUEST(request)->NameIdentifier = g_object_ref(nameIdentifier);

	return LASSO_NODE(request);
}
