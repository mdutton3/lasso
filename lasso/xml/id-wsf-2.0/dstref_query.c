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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "../private.h"
#include "dstref_query.h"
#include "idwsf2_strings.h"

/**
 * SECTION:dstref_query
 * @short_description: &lt;dstref:Query&gt;
 *
 * <figure><title>Schema fragment for dstref:Query</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "TestItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DstRefQuery, TestItem),
		"LassoIdWsf2DstRefTestItem", NULL, NULL },
	{ "QueryItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DstRefQuery, QueryItem),
		"LassoIdWsf2DstRefQueryItem", NULL, NULL },
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xml_insure_namespace(xmlnode, NULL, TRUE,
			LASSO_IDWSF2_DSTREF_QUERY(node)->hrefServiceType,
			LASSO_IDWSF2_DSTREF_QUERY(node)->prefixServiceType);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdWsf2DstRefQuery *object = LASSO_IDWSF2_DSTREF_QUERY(node);
	int res;

	res = parent_class->init_from_xml(node, xmlnode);
	if (res != 0) {
		return res;
	}

	object->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
	object->prefixServiceType = lasso_get_prefix_for_idwsf2_dst_service_href(
			object->hrefServiceType);
	if (object->prefixServiceType == NULL) {
		/* XXX: what to do here ? */
	}

	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


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
			NULL,
			NULL
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
	return g_object_new(LASSO_TYPE_IDWSF2_DSTREF_QUERY, NULL);
}
