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
#include "../../utils.h"
#include "samlp2_status_response.h"
#include "saml2_strings.h"
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

/**
 * SECTION:samlp2_status_response
 * @short_description: &lt;samlp2:StatusResponse&gt;
 *
 * <figure><title>Schema fragment for samlp2:StatusResponse</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="StatusResponseType">
 *   <sequence>
 *     <element ref="saml:Issuer" minOccurs="0"/>
 *     <element ref="ds:Signature" minOccurs="0"/>
 *     <element ref="samlp:Extensions" minOccurs="0"/>
 *     <element ref="samlp:Status"/>
 *   </sequence>
 *   <attribute name="ID" type="ID" use="required"/>
 *   <attribute name="InResponseTo" type="NCName" use="optional"/>
 *   <attribute name="Version" type="string" use="required"/>
 *   <attribute name="IssueInstant" type="dateTime" use="required"/>
 *   <attribute name="Destination" type="anyURI" use="optional"/>
 *   <attribute name="Consent" type="anyURI" use="optional"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Issuer", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Issuer),
		"LassoSaml2NameID", LASSO_SAML2_ASSERTION_PREFIX, LASSO_SAML2_ASSERTION_HREF},
	{ "Signature", SNIPPET_SIGNATURE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, ID), NULL, LASSO_DS_PREFIX, LASSO_DS_HREF},
	{ "Extensions", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Extensions), NULL, NULL, NULL},
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Status), NULL, NULL, NULL},
	{ "ID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, ID), NULL, NULL, NULL},
	{ "InResponseTo", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, InResponseTo), NULL, NULL, NULL},
	{ "Version", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Version), NULL, NULL, NULL},
	{ "IssueInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, IssueInstant), NULL, NULL, NULL},
	{ "Destination", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Destination), NULL, NULL, NULL},
	{ "Consent", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Consent), NULL, NULL, NULL},

	/* hidden fields; used in lasso dumps */
	{ "SignType", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, sign_type), NULL, NULL, NULL},
	{ "SignMethod", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, sign_method), NULL, NULL, NULL},
	{ "PrivateKeyFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, private_key_file), NULL, NULL, NULL},
	{ "CertificateFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, certificate_file), NULL, NULL, NULL},

	{NULL, 0, 0, NULL, NULL, NULL}
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
	ret = g_strdup_printf(LASSO_SAML2_FIELD_RESPONSE "=%s", deflated_message);
	lasso_release(deflated_message);
	return ret;
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	return lasso_node_init_from_saml2_query_fields(node, query_fields, NULL);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlp2StatusResponse *node)
{
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoSamlp2StatusResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "StatusResponse");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

	nclass->node_data->id_attribute_name = "ID";
	nclass->node_data->id_attribute_offset = G_STRUCT_OFFSET(LassoSamlp2StatusResponse, ID);
	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(
			LassoSamlp2StatusResponse, sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(
			LassoSamlp2StatusResponse, sign_method);
	nclass->node_data->private_key_file_offset = G_STRUCT_OFFSET(LassoSamlp2StatusResponse,
			private_key_file);
	nclass->node_data->certificate_file_offset = G_STRUCT_OFFSET(LassoSamlp2StatusResponse,
			certificate_file);
	nclass->node_data->keep_xmlnode = TRUE;
}

GType
lasso_samlp2_status_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlp2StatusResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlp2StatusResponse),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlp2StatusResponse", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp2_status_response_new:
 *
 * Creates a new #LassoSamlp2StatusResponse object.
 *
 * Return value: a newly created #LassoSamlp2StatusResponse object
 **/
LassoNode*
lasso_samlp2_status_response_new()
{
	return g_object_new(LASSO_TYPE_SAMLP2_STATUS_RESPONSE, NULL);
}
