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
#include "lib_status_response.h"
#include <libxml/uri.h>
#include "../utils.h"

/**
 * SECTION:lib_status_response
 * @short_description: &lt;lib:StatusResponse&gt;
 *
 * <figure><title>Schema fragment for lib:StatusResponse</title>
 * <programlisting><![CDATA[
 * <xs:complexType name="StatusResponseType">
 *   <xs:complexContent>
 *     <xs:extension base="samlp:ResponseAbstractType">
 *       <xs:sequence>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="ProviderID"/>
 *         <xs:element ref="samlp:Status"/>
 *         <xs:element ref="RelayState" minOccurs="0"/>
 *       </xs:sequence>
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
	{ "Extension", SNIPPET_EXTENSION,
		G_STRUCT_OFFSET(LassoLibStatusResponse, Extension), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibStatusResponse, ProviderID), NULL, NULL, NULL},
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoLibStatusResponse, Status), NULL, NULL, NULL},
	{ "RelayState", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoLibStatusResponse, RelayState), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static struct QuerySnippet query_snippets[] = {
	{ "ResponseID", NULL },
	{ "MajorVersion", NULL },
	{ "MinorVersion", NULL },
	{ "IssueInstant", NULL },
	{ "Recipient", NULL },
	{ "ProviderID", NULL },
	{ "Status", "Value" },
	{ "RelayState", NULL },
	{ "InResponseTo", NULL },
	{ NULL, NULL }
};

static LassoNodeClass *parent_class = NULL;

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	LassoLibStatusResponse *response = LASSO_LIB_STATUS_RESPONSE(node);
	gboolean rc;

	response->Status = lasso_samlp_status_new();
	rc = parent_class->init_from_query(node, query_fields);
	if (response->ProviderID == NULL || response->Status == NULL)
		return FALSE;

	if (response->Status->StatusCode) {
		LassoSamlpStatusCode *code = response->Status->StatusCode;
		if (code->Value && strchr(code->Value, ':') == NULL) {
			lasso_assign_string(code->Value,
					g_strdup_printf("samlp:%s", code->Value));
		}
	}

	return rc;
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibStatusResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "StatusResponse");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	lasso_node_class_add_query_snippets(nclass, query_snippets);
}

GType
lasso_lib_status_response_get_type()
{
	static GType status_response_type = 0;

	if (!status_response_type) {
		static const GTypeInfo status_response_info = {
			sizeof (LassoLibStatusResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibStatusResponse),
			0,
			NULL,
			NULL
		};

		status_response_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
				"LassoLibStatusResponse", &status_response_info, 0);
	}
	return status_response_type;
}

/**
 * lasso_lib_status_response_new:
 *
 * Creates a new #LassoLibStatusResponse object.
 *
 * Return value: a newly created #LassoLibStatusResponse object
 **/
LassoNode* lasso_lib_status_response_new()
{
	return g_object_new(LASSO_TYPE_LIB_STATUS_RESPONSE, NULL);
}
