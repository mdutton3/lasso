/* $Id: dstref_query.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#include "dstref_query.h"

/*
 * Schema fragment (liberty-idwsf-dst-ref-v2.1.xsd):
 *
 * <xs:complexType name="QueryType">
 *   <xs:complexContent>
 *     <xs:extension base="dst:RequestType">
 *       <xs:sequence>
 *         <xs:element ref="dstref:TestItem" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="dstref:QueryItem" minOccurs="0" maxOccurs="unbounded"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "TestItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DstRefQuery, TestItem),
		"LassoIdWsf2DstRefTestItem" },
	{ "QueryItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DstRefQuery, QueryItem),
		"LassoIdWsf2DstRefQueryItem" },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	xmlNs *ns;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_IDWSF2_DSTREF_QUERY(node)->hrefServiceType,
			(xmlChar*)LASSO_IDWSF2_DSTREF_QUERY(node)->prefixServiceType);
	xml_insure_namespace(xmlnode, ns, TRUE);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdWsf2DstRefQuery *query = LASSO_IDWSF2_DSTREF_QUERY(node);
	int res;

	res = parent_class->init_from_xml(node, xmlnode);
	if (res != 0) {
		return res;
	}

	query->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
	query->prefixServiceType = lasso_get_prefix_for_idwsf2_dst_service_href(
			query->hrefServiceType);
	if (query->prefixServiceType == NULL) {
		/* XXX: what to do here ? */
	}

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DstRefQuery *node)
{
	node->TestItem = NULL;
	node->QueryItem = NULL;
	node->prefixServiceType = NULL;
	node->hrefServiceType = NULL;
}

static void
class_init(LassoIdWsf2DstRefQueryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Query");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DSTREF_HREF, LASSO_IDWSF2_DSTREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_dstref_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DstRefQueryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DstRefQuery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_DST_REQUEST,
				"LassoIdWsf2DstRefQuery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_dstref_query_new:
 *
 * Creates a new #LassoIdWsf2DstRefQuery object.
 *
 * Return value: a newly created #LassoIdWsf2DstRefQuery object
 **/
LassoIdWsf2DstRefQuery*
lasso_idwsf2_dstref_query_new()
{
	return LASSO_IDWSF2_DSTREF_QUERY(g_object_new(LASSO_TYPE_IDWSF2_DSTREF_QUERY, NULL));
}
