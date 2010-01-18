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

#include <lasso/id-ff/service.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar*
lasso_service_dump(LassoService *service)
{
	return lasso_node_dump(LASSO_NODE(service));
}

void
lasso_service_destroy(LassoService *service)
{
	lasso_node_destroy(LASSO_NODE(service));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "type", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoService, type) },
	{ "endpoint", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoService, endpoint) },
	{ "ServiceDumpVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoService, ServiceDumpVersion) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoService *service)
{
	service->type = NULL;
	service->endpoint = NULL;
	service->ServiceDumpVersion = 1;
}

static void
class_init(LassoServiceClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Service");
	lasso_node_class_set_ns(nclass, NULL, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
						   "LassoService", &this_info, 0);
	}
	return this_type;
}

LassoService*
lasso_service_new(const gchar *type,
		  const gchar *endpoint)
{
	LassoService *service;

	service = g_object_new(LASSO_TYPE_SERVICE, NULL);

	service->type = g_strdup(type);
	service->endpoint = g_strdup(endpoint);

	return service;
}

LassoService*
lasso_service_new_from_dump(const gchar *dump)
{
	LassoService *service;
	xmlDoc *doc;

	service = g_object_new(LASSO_TYPE_SERVICE, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	lasso_node_init_from_xml(LASSO_NODE(service), xmlDocGetRootElement(doc));
	xmlFreeDoc(doc);

	return service;
}
