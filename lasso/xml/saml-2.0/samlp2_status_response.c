/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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


#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include "samlp2_status_response.h"

/*
 * Schema fragment (saml-schema-protocol-2.0.xsd):
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
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Issuer", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Issuer),
		"LassoSaml2NameID" },
	{ "Extensions", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Extensions) },
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Status) },
	{ "ID", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, ID) },
	{ "InResponseTo", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, InResponseTo) },
	{ "Version", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Version) },
	{ "IssueInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, IssueInstant) },
	{ "Destination", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Destination) },
	{ "Consent", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, Consent) },
	{ "Signature", SNIPPET_SIGNATURE,
		G_STRUCT_OFFSET(LassoSamlp2StatusResponse, ID) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;



static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoSamlp2StatusResponse *request = LASSO_SAMLP2_STATUS_RESPONSE(node);
	xmlNode *xmlnode;
	int rc;
	
	xmlnode = parent_class->get_xmlNode(node, lasso_dump);

	if (lasso_dump == FALSE && request->sign_type) {
		rc = lasso_sign_node(xmlnode, "ID", request->ID,
				request->private_key_file, request->certificate_file);
		/* signature may have failed; what to do ? */
	}

	return xmlnode;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlp2StatusResponse *node)
{
	node->Issuer = NULL;
	node->Extensions = NULL;
	node->Status = NULL;
	node->ID = NULL;
	node->InResponseTo = NULL;
	node->Version = NULL;
	node->IssueInstant = NULL;
	node->Destination = NULL;
	node->Consent = NULL;
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoSamlp2StatusResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "StatusResponse"); 
	lasso_node_class_set_ns(nclass, LASSO_SAML2_PROTOCOL_HREF, LASSO_SAML2_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(
			LassoSamlp2StatusResponse, sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(
			LassoSamlp2StatusResponse, sign_method);
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
