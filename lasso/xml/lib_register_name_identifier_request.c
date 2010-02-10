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

#include "./private.h"
#include "./lib_register_name_identifier_request.h"
#include "../utils.h"

/**
 * SECTION:lib_register_name_identifier_request
 * @short_description: &lt;lib:RegisterNameIdentifierRequest&gt;
 *
 * <figure><title>Schema fragment for lib:RegisterNameIdentifierRequest</title>
 * <programlisting><![CDATA[
 * <xs:element name="RegisterNameIdentifierRequest" type="RegisterNameIdentifierRequestType"/>
 * <xs:complexType name="RegisterNameIdentifierRequestType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:RequestAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="IDPProvidedNameIdentifier"/>
 *         <xs:element ref="SPProvidedNameIdentifier" minOccurs="0"/>
 *         <xs:element ref="OldProvidedNameIdentifier"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * <xs:element name="IDPProvidedNameIdentifier" type="saml:NameIdentifierType"/>
 * <xs:element name="SPProvidedNameIdentifier" type="saml:NameIdentifierType"/>
 * <xs:element name="OldProvidedNameIdentifier" type="saml:NameIdentifierType"/>
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
	{ "Extension", SNIPPET_EXTENSION,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, ProviderID), NULL, NULL, NULL},
	{ "IDPProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, IDPProvidedNameIdentifier), NULL, NULL, NULL},
	{ "SPProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, SPProvidedNameIdentifier), NULL, NULL, NULL},
	{ "OldProvidedNameIdentifier", SNIPPET_NAME_IDENTIFIER,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, OldProvidedNameIdentifier), NULL, NULL, NULL},
	{ "RelayState", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoLibRegisterNameIdentifierRequest, RelayState), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static struct QuerySnippet query_snippets[] = {
	{ "RequestID", NULL },
	{ "MajorVersion", NULL },
	{ "MinorVersion", NULL },
	{ "IssueInstant", NULL },
	{ "ProviderID", NULL },
	{ "IDPProvidedNameIdentifier/NameQualifier", "IDPNameQualifier"},
	{ "IDPProvidedNameIdentifier/Format", "IDPNameFormat"},
	{ "IDPProvidedNameIdentifier/content", "IDPProvidedNameIdentifier"},
	{ "SPProvidedNameIdentifier/NameQualifier", "SPNameQualifier"},
	{ "SPProvidedNameIdentifier/Format", "SPNameFormat"},
	{ "SPProvidedNameIdentifier/content", "SPProvidedNameIdentifier"},
	{ "OldProvidedNameIdentifier/NameQualifier", "OldNameQualifier"},
	{ "OldProvidedNameIdentifier/Format", "OldNameFormat"},
	{ "OldProvidedNameIdentifier/content", "OldProvidedNameIdentifier"},
	{ "RelayState", NULL },
	{ NULL, NULL }
};

static LassoNodeClass *parent_class = NULL;

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibRegisterNameIdentifierRequest *request;
	gboolean rc;

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(node);

	request->IDPProvidedNameIdentifier = lasso_saml_name_identifier_new();
	request->SPProvidedNameIdentifier = lasso_saml_name_identifier_new();
	request->OldProvidedNameIdentifier = lasso_saml_name_identifier_new();

	rc = parent_class->init_from_query(node, query_fields);

	if (request->IDPProvidedNameIdentifier->content == NULL) {
		lasso_release_gobject(request->IDPProvidedNameIdentifier);
	}
	if (request->SPProvidedNameIdentifier->content == NULL) {
		lasso_release_gobject(request->SPProvidedNameIdentifier);
	}
	if (request->OldProvidedNameIdentifier->content == NULL) {
		lasso_release_gobject(request->OldProvidedNameIdentifier);
	}

	if (request->ProviderID == NULL ||
			request->OldProvidedNameIdentifier == NULL ||
			request->IDPProvidedNameIdentifier == NULL) {
		return FALSE;
	}

	return rc;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibRegisterNameIdentifierRequestClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RegisterNameIdentifierRequest");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	lasso_node_class_add_query_snippets(nclass, query_snippets);
}

GType
lasso_lib_register_name_identifier_request_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibRegisterNameIdentifierRequestClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibRegisterNameIdentifierRequest),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
				"LassoLibRegisterNameIdentifierRequest", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_lib_register_name_identifier_request_new:
 *
 * Creates a new #LassoLibRegisterNameIdentifierRequest object.
 *
 * Return value: a newly created #LassoLibRegisterNameIdentifierRequest object
 **/
LassoNode*
lasso_lib_register_name_identifier_request_new()
{
	return g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, NULL);
}


/**
 * lasso_lib_register_name_identifier_request_new_full:
 * @providerID: the providerID of the requester
 * @idpNameIdentifier: a #LassoSamlNameIdentifier object, giving the new idp provided name
 * identifier
 * @spNameIdentifier: a #LassoSamlNameIdentifier object, giving the new sp provided name identifier
 * @oldNameIdentifier: a #LassoSamlNameIdentifier object, giving the old name identifier
 * @sign_type: a #LassoSignatureType value
 * @sign_method: a #LassoSignatureMethod value
 *
 * Creates a new #LassoLibRegisterNameIdentifierRequest object and initializes
 * it with the parameters.
 *
 * Return value: a newly created #LassoLibRegisterNameIdentifierRequest object
 **/
LassoNode*
lasso_lib_register_name_identifier_request_new_full(const char *providerID,
		LassoSamlNameIdentifier *idpNameIdentifier,
		LassoSamlNameIdentifier *spNameIdentifier,
		LassoSamlNameIdentifier *oldNameIdentifier,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method)
{
	LassoLibRegisterNameIdentifierRequest *request;
	LassoSamlpRequestAbstract *request_base;

	request = g_object_new(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, NULL);
	request_base = LASSO_SAMLP_REQUEST_ABSTRACT(request);

	request_base->RequestID = lasso_build_unique_id(32);
	request_base->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	request_base->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	request_base->IssueInstant = lasso_get_current_time();
	request_base->sign_type = sign_type;
	request_base->sign_method = sign_method;

	request->ProviderID = g_strdup(providerID);
	request->IDPProvidedNameIdentifier = idpNameIdentifier;
	request->SPProvidedNameIdentifier = spNameIdentifier;
	request->OldProvidedNameIdentifier = oldNameIdentifier;

	return LASSO_NODE(request_base);
}
