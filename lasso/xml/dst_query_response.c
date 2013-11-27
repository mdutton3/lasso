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
#include "dst_query_response.h"
#include "idwsf_strings.h"

/**
 * SECTION:dst_query_response
 * @short_description: &lt;dst:QueryResponse&gt;
 *
 * <figure><title>Schema fragment for dst:QueryResponse</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="QueryResponse" type="QueryResponseType"/>
 * <xs:complexType name="QueryResponseType">
 *   <xs:sequence>
 *     <xs:element ref="Status"/>
 *     <xs:element name="Data" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID"/>
 *   <xs:attribute name="itemIDRef" type="IDReferenceType"/>
 *   <xs:attribute name="timeStamp" type="xs:dateTime"/>
 * </xs:complexType>
 *
 * Schema fragment (liberty-idwsf-utility-1.0-errata-v1.0.xsd):
 *
 * <xs:simpleType name="IDReferenceType">
 *   <xs:annotation>
 *     <xs:documentation> This type can be used when referring to elements that are
 *       identified using an IDType </xs:documentation>
 *     </xs:annotation>
 *   <xs:restriction base="xs:string"/>
 * </xs:simpleType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstQueryResponse, Status), NULL, NULL, NULL},
	{ "Data", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDstQueryResponse, Data), NULL, NULL, NULL},
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoDstQueryResponse, Extension), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQueryResponse, id), NULL, NULL, NULL},
	{ "itemIDRef", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoDstQueryResponse, itemIDRef), NULL, NULL, NULL},
	{ "timeStamp", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoDstQueryResponse, timeStamp), NULL, NULL, NULL},
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
	ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_DST_QUERY_RESPONSE(node)->hrefServiceType,
			(xmlChar*)LASSO_DST_QUERY_RESPONSE(node)->prefixServiceType);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc = 0;
	LassoDstQueryResponse *response = LASSO_DST_QUERY_RESPONSE(node);

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	response->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
	response->prefixServiceType = lasso_get_prefix_for_dst_service_href(
			response->hrefServiceType);
	if (response->prefixServiceType == NULL) {
		/* XXX: what to do here ? */
	}

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDstQueryResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "QueryResponse");
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_dst_query_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstQueryResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstQueryResponse),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstQueryResponse", &this_info, 0);
	}
	return this_type;
}

LassoDstQueryResponse*
lasso_dst_query_response_new(LassoUtilityStatus *status)
{
	LassoDstQueryResponse *node;

	g_return_val_if_fail(LASSO_IS_UTILITY_STATUS(status), NULL);

	node = g_object_new(LASSO_TYPE_DST_QUERY_RESPONSE, NULL);

	node->Status = status;

	return node;
}

