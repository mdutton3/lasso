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

#include "errors.h"

#include <lasso/xml/disco_requested_service_type.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

#define snippets() \
	LassoDiscoRequestedServiceType *RequestedServiceType = LASSO_DISCO_REQUESTED_SERVICE_TYPE(node); \
	struct XmlSnippet snippets[] = { \
		{ "ServiceType", SNIPPET_CONTENT, (void**)&RequestedServiceType->ServiceType }, \
		{ "Options", SNIPPET_NODE, (void**)&RequestedServiceType->Options }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	GList *option;
	xmlNode *xmlnode, *options_xmlNode;
	snippets();

	xmlnode = xmlNewNode(NULL, "RequestedServiceType");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));
	
	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	xmlNode *option_xmlNode;
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
instance_init(LassoDiscoRequestedServiceType *node)
{
	node->ServiceType = NULL;
	node->Options = NULL;
}

static void
class_init(LassoDiscoRequestedServiceTypeClass *class)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(class);

	parent_class = g_type_class_peek_parent(class);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType lasso_disco_requested_service_type_get_type() {
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoRequestedServiceTypeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoRequestedServiceType),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoRequestedServiceType", &this_info, 0);
	}
	return this_type;
}

LassoDiscoRequestedServiceType*
lasso_disco_requested_service_type_new(const char *ServiceType)
{
	LassoDiscoRequestedServiceType *node;

	node = g_object_new(LASSO_TYPE_DISCO_REQUESTED_SERVICE_TYPE, NULL);

	node->ServiceType = g_strdup(ServiceType);

	return node;
}
