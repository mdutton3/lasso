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
#include "samlp_response.h"
#include <libxml/tree.h>

/**
 * SECTION:samlp_response
 * @short_description: &lt;samlp:Response&gt;
 *
 * <figure><title>Schema fragment for samlp:Response</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlpResponse, Status), NULL, NULL, NULL},
	{ "Assertion", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoSamlpResponse, Assertion), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


static gboolean
has_lib_status(LassoSamlpStatusCode *status_code)
{
	if (status_code == NULL)
		return FALSE;
	if (strncmp(status_code->Value, "lib", 3) == 0)
		return TRUE;
	return has_lib_status(status_code->StatusCode);
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode, *t;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);

	if (LASSO_SAMLP_RESPONSE(node)->Status &&
			has_lib_status(LASSO_SAMLP_RESPONSE(node)->Status->StatusCode)) {
		/* liberty QName, add liberty namespace */
		xmlNewNs(xmlnode, (xmlChar*)LASSO_LIB_HREF, (xmlChar*)LASSO_LIB_PREFIX);
	}


	for (t = xmlnode->children; t && strcmp((char*)t->name, "Assertion"); t = t->next) ;

	if (t && strcmp((char*)t->ns->href, LASSO_LIB_HREF) == 0) {
		/* liberty nodes are not allowed in samlp nodes */
		xmlSetNs(t, xmlNewNs(xmlnode, (xmlChar*)LASSO_SAML_ASSERTION_HREF,
					(xmlChar*)LASSO_SAML_ASSERTION_PREFIX));
		if (xmlHasNsProp(t, (xmlChar*)"type", (xmlChar*)LASSO_XSI_HREF) == NULL)
			xmlNewNsProp(t, xmlNewNs(xmlnode,
						(xmlChar*)LASSO_XSI_HREF,
						(xmlChar*)LASSO_XSI_PREFIX),
					(xmlChar*)"type", (xmlChar*)"lib:AssertionType");
	}

	return xmlnode;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlpResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->node_data->keep_xmlnode = TRUE;
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
			NULL,
			NULL
		};

		response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT ,
				"LassoSamlpResponse", &response_info, 0);
	}
	return response_type;
}


/**
 * lasso_samlp_response_new:
 *
 * Creates a new #LassoSamlpResponse object.
 *
 * Return value: a newly created #LassoSamlpResponse object
 **/
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

	/* Add Status */
	status = LASSO_SAMLP_STATUS(lasso_samlp_status_new());
	status_code = LASSO_SAMLP_STATUS_CODE(lasso_samlp_status_code_new());
	status_code->Value = g_strdup(LASSO_SAML_STATUS_CODE_REQUEST_DENIED);
	status->StatusCode = status_code;
	LASSO_SAMLP_RESPONSE(response)->Status = status;

	return LASSO_NODE(response);
}
