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

#include "private.h"
#include "../utils.h"
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include "samlp_request_abstract.h"

/**
 * SECTION:samlp_request_abstract
 * @short_description: &lt;samlp:RequestAbstractType&gt;
 *
 * <figure><title>Schema fragment for samlp:RequestAbstractType</title>
 * <programlisting><![CDATA[
 *
 * <complexType name="RequestAbstractType" abstract="true">
 *   <sequence>
 *     <element ref="samlp:RespondWith" minOccurs="0" maxOccurs="unbounded"/>
 *     <element ref="ds:Signature" minOccurs="0"/>
 *   </sequence>
 *   <attribute name="RequestID" type="saml:IDType" use="required"/>
 *   <attribute name="MajorVersion" type="integer" use="required"/>
 *   <attribute name="MinorVersion" type="integer" use="required"/>
 *   <attribute name="IssueInstant" type="dateTime" use="required"/>
 * </complexType>
 *
 * <element name="RespondWith" type="QName"/>
 *
 * From oasis-sstc-saml-schema-assertion-1.0.xsd:
 * <simpleType name="IDType">
 *   <restriction base="string"/>
 * </simpleType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "RespondWith", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, RespondWith), NULL, NULL, NULL},
	{ "Signature", SNIPPET_SIGNATURE,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, RequestID), NULL, LASSO_DS_PREFIX, LASSO_DS_HREF},
	{ "RequestID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlpRequestAbstract, RequestID), NULL, NULL, NULL},
	{ "MajorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, MajorVersion), NULL, NULL, NULL},
	{ "MinorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, MinorVersion), NULL, NULL, NULL},
	{ "IssueInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlpRequestAbstract, IssueInstant), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlpRequestAbstract *node)
{
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoSamlpRequestAbstractClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "RequestAbstract");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	nclass->node_data->id_attribute_name = "RequestID";
	nclass->node_data->id_attribute_offset = G_STRUCT_OFFSET(LassoSamlpRequestAbstract,
			RequestID);
	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(
			LassoSamlpRequestAbstract, sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(
			LassoSamlpRequestAbstract, sign_method);
	nclass->node_data->private_key_file_offset = G_STRUCT_OFFSET(LassoSamlpRequestAbstract,
			private_key_file);
	nclass->node_data->certificate_file_offset = G_STRUCT_OFFSET(LassoSamlpRequestAbstract,
			certificate_file);
}

GType
lasso_samlp_request_abstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpRequestAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpRequestAbstract),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlpRequestAbstract", &this_info, 0);
	}
	return this_type;
}

