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

#include <lasso/xml/dst_query_response.h>


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDstQueryResponse *query_response = LASSO_DST_QUERY_RESPONSE(node); \
	struct XmlSnippetObsolete snippets[] = { \
		{ "Status", SNIPPET_NODE, (void**)&(query_response->Status) }, \
		{ NULL, 0, NULL } \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "QueryResponse");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, NULL, NULL));

	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();
	
	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	init_xml_with_snippets(xmlnode, snippets);

	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDstQueryResponse *node)
{
	node->Status = NULL;
	node->Data = NULL;
	/* FIXME : implement Extension element */

	node->id = NULL;
	node->itemIDRef = NULL;
	node->timeStamp = NULL;
}

static void
class_init(LassoDstQueryResponseClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
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
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstQueryResponse", &this_info, 0);
	}
	return this_type;
}

LassoDstQueryResponse*
lasso_dst_query_response_new(LassoUtilityStatus *Status,
			     const char *id,
			     const char *itemIDRef,
			     const char *timeStamp)
{
	LassoDstQueryResponse *node;

	node = g_object_new(LASSO_TYPE_DST_QUERY_RESPONSE, NULL);

	node->Status = Status;

	node->id = g_strdup(id);
	node->itemIDRef = g_strdup(itemIDRef);
	node->timeStamp = g_strdup(timeStamp);

	return node;
}

