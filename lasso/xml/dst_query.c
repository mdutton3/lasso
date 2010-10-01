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
#include "dst_query.h"
#include "./idwsf_strings.h"

/**
 * SECTION:dst_query
 * @short_description: &lt;dst:Query&gt;
 *
 * <figure><title>Schema fragment for dst:Query</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstQuery, ResourceID), NULL, NULL, NULL},
	{ "EncryptedResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstQuery,
			EncryptedResourceID), NULL, NULL, NULL },
	{ "QueryItem", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDstQuery, QueryItem), NULL, NULL, NULL},
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoDstQuery, Extension), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQuery, id), NULL, NULL, NULL},
	{ "itemID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstQuery, itemID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	xmlNode *t = xmlnode->children;

	xmlSetNs(xmlnode, ns);
	while (t) {
		if (t->type == XML_ELEMENT_NODE && t->ns == NULL) {
			insure_namespace(t, ns);
		}
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
	LassoDstQuery *query = LASSO_DST_QUERY(node);
	int rc = 0;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) {
		return rc;
	}

	query->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
	query->prefixServiceType = lasso_get_prefix_for_dst_service_href(
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
			NULL,
			NULL
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

	if (queryItem) {
		query->QueryItem = g_list_append(query->QueryItem, queryItem);
	}

	return query;
}

