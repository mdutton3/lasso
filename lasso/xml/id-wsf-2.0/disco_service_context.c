/* $Id: disco_service_context.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "disco_service_context.h"
#include "idwsf2_strings.h"

/**
 * SECTION:disco_service_context
 * @short_description: &lt;disco:ServiceContext&gt;
 *
 * <figure><title>Schema fragment for disco:ServiceContext</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ServiceContextType">
 *   <xs:sequence>
 *     <xs:element ref="ServiceType"     maxOccurs="unbounded" />
 *     <xs:element ref="Options"         minOccurs="0"
 *       maxOccurs="unbounded" />
 *       <xs:element ref="EndpointContext" maxOccurs="unbounded" />
 *     </xs:sequence>
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "ServiceType", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoServiceContext, ServiceType), NULL, NULL, NULL},
	{ "Options", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoServiceContext, Options),
		"LassoIdWsf2DiscoOptions", NULL, NULL },
	{ "EndpointContext", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoServiceContext, EndpointContext),
		"LassoIdWsf2DiscoEndpointContext", NULL, NULL },
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DiscoServiceContextClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ServiceContext");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCOVERY_HREF, LASSO_IDWSF2_DISCOVERY_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_service_context_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoServiceContextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoServiceContext),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoServiceContext", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_service_context_new:
 *
 * Creates a new #LassoIdWsf2DiscoServiceContext object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoServiceContext object
 **/
LassoIdWsf2DiscoServiceContext*
lasso_idwsf2_disco_service_context_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT, NULL);
}


LassoIdWsf2DiscoServiceContext*
lasso_idwsf2_disco_service_context_new_full(
		const gchar *serviceType, LassoIdWsf2DiscoEndpointContext *endpointContext)
{
	LassoIdWsf2DiscoServiceContext *context;

	context = lasso_idwsf2_disco_service_context_new();

	context->ServiceType = g_list_append(NULL, g_strdup(serviceType));
	context->EndpointContext = g_list_append(NULL, g_object_ref(endpointContext));

	return context;
}
