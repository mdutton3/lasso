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

#include <lasso/xml/dst_query.h>

/*
 * Schema fragment (liberty-idwsf-dst-v1.0.xsd):
 *
 * <xs:element name="Query" type="QueryType"/>
 * <xs:complexType name="QueryType">
 *     <xs:sequence>
 *         <xs:group ref="ResourceIDGroup" minOccurs="0"/>
 *	   <xs:element name="QueryItem" maxOccurs="unbounded"/>
 *	   <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *     </xs:sequence>
 *     <xs:attribute name="id" type="xs:ID"/>
 *     <xs:attribute name="itemID" type="IDType"/>
 * </xs:complexType>
 *
 * <xs:simpleType name="IDReferenceType">
 *   <xs:annotation>
 *     <xs:documentation> This type can be used when referring to elements that are
 *       identified using an IDType </xs:documentation>
 *     </xs:annotation>
 *   <xs:restriction base="xs:string"/>
 * </xs:simpleType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstQuery, ResourceID) },
	{ "EncryptedResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstQuery,
							       EncryptedResourceID) },
	{ "QueryItem", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDstQuery, QueryItem) },
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoDstQuery, Extension) },
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQuery, id) },
	{ "itemID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQuery, itemID) },
	{NULL, 0, 0}
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
	ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_DST_QUERY(node)->hrefServiceType,
			(xmlChar*)LASSO_DST_QUERY(node)->prefixServiceType);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc;
	LassoDstQuery *query = LASSO_DST_QUERY(node);

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	if (strcmp((char*)xmlnode->ns->href, LASSO_PP_HREF) == 0) {
		query->hrefServiceType = g_strdup(LASSO_PP_HREF);
		query->prefixServiceType = g_strdup(LASSO_PP_PREFIX);
	} else if (strcmp((char*)xmlnode->ns->href, LASSO_EP_HREF) == 0) {
		query->hrefServiceType = g_strdup(LASSO_EP_HREF);
		query->prefixServiceType = g_strdup(LASSO_EP_PREFIX);
	} else {
		/* XXX */
	}

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDstQuery *node)
{
	node->ResourceID = NULL;
	node->EncryptedResourceID = NULL;
	node->QueryItem = NULL;
	node->id = NULL;
	node->itemID = NULL;
	node->prefixServiceType = NULL;
	node->hrefServiceType = NULL;
}

static void
class_init(LassoDstQueryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Query");
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_dst_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstQueryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstQuery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstQuery", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_dst_query_new:
 * @query_item: query item to embed in request (optional)
 *
 * Creates a new #LassoDstQuery object.  If @query_item is set it is added to
 * the requested query items.
 *
 * Return value: a newly created #LassoDstQuery object.
 **/
LassoDstQuery*
lasso_dst_query_new(LassoDstQueryItem *queryItem)
{
	LassoDstQuery *query;

	query = g_object_new(LASSO_TYPE_DST_QUERY, NULL);

	if (queryItem)
		query->QueryItem = g_list_append(query->QueryItem, queryItem);

	return query;
}

