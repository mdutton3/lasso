/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/samlp_response.h>
#include <libxml/tree.h>

/*
 * Schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):
 * 
 * <element name="Response" type="samlp:ResponseType"/>
 * <complexType name="ResponseType">
 *   <complexContent>
 *     <extension base="samlp:ResponseAbstractType">
 *       <sequence>
 *         <element ref="samlp:Status"/>
 *         <element ref="saml:Assertion" minOccurs="0" maxOccurs="unbounded"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Assertion", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlpResponse, Assertion) },
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlpResponse, Status) },
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode, *t;

	xmlnode = parent_class->get_xmlNode(node);

	for (t = xmlnode->children; t && strcmp(t->name, "Assertion"); t = t->next) ;

	if (t && strcmp(t->ns->href, LASSO_LIB_HREF) == 0) {
		/* liberty nodes are not allowed in samlp nodes */
		xmlSetNs(t, xmlNewNs(xmlnode, LASSO_SAML_ASSERTION_HREF,
					LASSO_SAML_ASSERTION_PREFIX));
		if (xmlHasNsProp(t, "type", LASSO_XSI_HREF) == NULL)
			xmlNewNsProp(t, xmlNewNs(xmlnode, LASSO_XSI_HREF, LASSO_XSI_PREFIX),
					"type", "lib:AssertionType");
	}

	return xmlnode;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlpResponse *node)
{
	node->Assertion = NULL;
	node->Status = NULL;
}

static void
class_init(LassoSamlpResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Response");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp_response_get_type()
{
	static GType response_type = 0;

	if (!response_type) {
		static const GTypeInfo response_info = {
			sizeof (LassoSamlpResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT ,
				"LassoSamlpResponse", &response_info, 0);
	}
	return response_type;
}

LassoNode*
lasso_samlp_response_new()
{
	LassoSamlpResponseAbstract *response;
	LassoSamlpStatusCode *status_code;
	LassoSamlpStatus *status;

	response = g_object_new(LASSO_TYPE_SAMLP_RESPONSE, NULL);

	response->ResponseID = lasso_build_unique_id(32);
	response->MajorVersion = LASSO_SAML_MAJOR_VERSION_N;
	response->MinorVersion = LASSO_SAML_MINOR_VERSION_N;
	response->IssueInstant = lasso_get_current_time();
	/* XXX: shouldn't ->InResponseTo be set ? */

	/* Add Status */
	status = LASSO_SAMLP_STATUS(lasso_samlp_status_new());
	status_code = LASSO_SAMLP_STATUS_CODE(lasso_samlp_status_code_new());
	status_code->Value = LASSO_SAML_STATUS_CODE_SUCCESS;
	status->StatusCode = status_code;
	LASSO_SAMLP_RESPONSE(response)->Status = status;

	return LASSO_NODE(response);
}

