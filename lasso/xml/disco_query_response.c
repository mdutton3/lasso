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
#include "disco_query_response.h"
#include "./idwsf_strings.h"

/**
 * SECTION:disco_query_response
 * @short_description: &lt;disco:QueryResponse&gt;
 *
 * <figure><title>Schema fragment for disco:QueryResponse</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="QueryResponse" type="QueryResponseType"/>
 * <xs:complexType name="QueryResponseType">
 *   <xs:sequence>
 *     <xs:element ref="Status"/>
 *     <xs:element ref="ResourceOffering" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="Credentials" minOccurs="0">
 *       <xs:complexType>
 *         <xs:sequence>
 *           <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *       </xs:complexType>
 *     </xs:element>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoQueryResponse, Status), NULL, NULL, NULL},
	{ "ResourceOffering", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoDiscoQueryResponse, ResourceOffering), NULL, NULL, NULL},
	{ "Credentials", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoDiscoQueryResponse, Credentials), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoDiscoQueryResponse, id), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	xmlNode *t = xmlnode->children;

	xmlSetNs(xmlnode, ns);
	while (t) {
		if (t->type == XML_ELEMENT_NODE && t->ns == NULL)
			insure_namespace(t, ns);
		t = t->next;
	}
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	xmlNs *ns;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	ns = xmlNewNs(NULL, (xmlChar*)LASSO_DISCO_HREF, (xmlChar*)LASSO_DISCO_PREFIX);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoQueryResponseClass *class)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(class);

	parent_class = g_type_class_peek_parent(class);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "QueryResponse");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_query_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoQueryResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoQueryResponse),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoQueryResponse", &this_info, 0);
	}
	return this_type;
}

LassoDiscoQueryResponse*
lasso_disco_query_response_new(LassoUtilityStatus *status)
{
	LassoDiscoQueryResponse *node;

	g_return_val_if_fail(LASSO_IS_UTILITY_STATUS(status), NULL);

	node = g_object_new(LASSO_TYPE_DISCO_QUERY_RESPONSE, NULL);

	node->Status = status;

	return node;
}
