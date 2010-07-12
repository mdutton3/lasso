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
#include "../utils.h"
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include "samlp_response_abstract.h"

/**
 * SECTION:samlp_response_abstract
 * @short_description: &lt;samlp:ResponseAbstractType&gt;
 *
 * <figure><title>Schema fragment for samlp:ResponseAbstractType</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="ResponseAbstractType" abstract="true">
 *   <sequence>
 *      <element ref="ds:Signature" minOccurs="0"/>
 *   </sequence>
 *   <attribute name="ResponseID" type="saml:IDType" use="required"/>
 *   <attribute name="InResponseTo" type="saml:IDReferenceType" use="optional"/>
 *   <attribute name="MajorVersion" type="integer" use="required"/>
 *   <attribute name="MinorVersion" type="integer" use="required"/>
 *   <attribute name="IssueInstant" type="dateTime" use="required"/>
 *   <attribute name="Recipient" type="anyURI" use="optional"/>
 * </complexType>
 *
 * From oasis-sstc-saml-schema-assertion-1.0.xsd:
 * <simpleType name="IDType">
 *   <restriction base="string"/>
 * </simpleType>
 * <simpleType name="IDReferenceType">
 *   <restriction base="string"/>
 * </simpleType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Signature", SNIPPET_SIGNATURE,
		G_STRUCT_OFFSET(LassoSamlpResponseAbstract, ResponseID), NULL, NULL, NULL},
	{ "ResponseID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlpResponseAbstract, ResponseID), NULL, NULL, NULL},
	{ "MajorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlpResponseAbstract, MajorVersion), NULL, NULL, NULL},
	{ "MinorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlpResponseAbstract, MinorVersion), NULL, NULL, NULL},
	{ "IssueInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlpResponseAbstract, IssueInstant), NULL, NULL, NULL},
	{ "InResponseTo", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlpResponseAbstract, InResponseTo), NULL, NULL, NULL},
	{ "Recipient", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlpResponseAbstract, Recipient), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlpResponseAbstract *node)
{
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoSamlpResponseAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ResponseAbstract");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	nclass->node_data->id_attribute_name = "ResponseID";
	nclass->node_data->id_attribute_offset = G_STRUCT_OFFSET(LassoSamlpResponseAbstract,
			ResponseID);
	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(LassoSamlpResponseAbstract,
			sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(LassoSamlpResponseAbstract,
			sign_method);
	nclass->node_data->private_key_file_offset = G_STRUCT_OFFSET(LassoSamlpResponseAbstract,
			private_key_file);
	nclass->node_data->certificate_file_offset = G_STRUCT_OFFSET(LassoSamlpResponseAbstract,
			certificate_file);
}

GType
lasso_samlp_response_abstract_get_type()
{
	static GType response_abstract_type = 0;

	if (!response_abstract_type) {
		static const GTypeInfo response_abstract_info = {
			sizeof (LassoSamlpResponseAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpResponseAbstract),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		response_abstract_type = g_type_register_static(LASSO_TYPE_NODE ,
				"LassoSamlpResponseAbstract",
				&response_abstract_info, 0);
	}
	return response_abstract_type;
}

void
lasso_samlp_response_abstract_fill(LassoSamlpResponseAbstract *response,
		const char *InResponseTo, const char *Recipient)
{
	response->ResponseID = lasso_build_unique_id(32);
	response->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	response->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	response->IssueInstant = lasso_get_current_time();
	response->InResponseTo = g_strdup(InResponseTo);
	response->Recipient = g_strdup(Recipient);
}
