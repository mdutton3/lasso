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

#include <lasso/xml/dst_data.h>


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDstData *data = LASSO_DST_DATA(node); \
	struct XmlSnippetObsolete snippets[] = { \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "Data");
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
instance_init(LassoDstData *node)
{

}

static void
class_init(LassoDstDataClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_dst_data_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstDataClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstData),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstData", &this_info, 0);
	}
	return this_type;
}

LassoDstData*
lasso_dst_data_new(const char *itemIDRef)
{
	LassoDstData *data;

	data = g_object_new(LASSO_TYPE_DST_DATA, NULL);

	return data;
}

