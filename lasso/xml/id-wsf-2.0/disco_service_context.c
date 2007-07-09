/* $Id: disco_service_context.c 2261 2005-01-27 23:41:05 $ 
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

#include <lasso/xml/id-wsf-2.0/disco_service_context.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-v2.0.xsd):
 * 
 * <xs:element name="ServiceContext" type="ServiceContextType"/>
 * <xs:complexType name="ServiceContextType">
 *    <xs:sequence>
 *       <xs:element ref="ServiceType"     maxOccurs="unbounded" />
 *       <xs:element ref="Options"         minOccurs="0"
 *                                         maxOccurs="unbounded" />
 *       <xs:element ref="EndpointContext" maxOccurs="unbounded" />
 *    </xs:sequence>
 * </xs:complexType>
 * 
 * <xs:element name="ServiceType" type="xs:anyURI"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ServiceType", SNIPPET_CONTENT,
	  G_STRUCT_OFFSET(LassoIdWsf2DiscoServiceContext, ServiceType) },
	{ "Options", SNIPPET_NODE,
	  G_STRUCT_OFFSET(LassoIdWsf2DiscoServiceContext, Options) },
	{ "EndpointContext", SNIPPET_NODE,
	  G_STRUCT_OFFSET(LassoIdWsf2DiscoServiceContext, EndpointContext) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DiscoServiceContext *node)
{
	node->ServiceType = NULL;
	node->Options = NULL;
	node->EndpointContext = NULL;
}

static void
class_init(LassoIdWsf2DiscoServiceContextClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ServiceContext");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF, LASSO_IDWSF2_DISCO_PREFIX);
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
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoServiceContext", &this_info, 0);
	}
	return this_type;
}

LassoIdWsf2DiscoServiceContext*
lasso_idwsf2_disco_service_context_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT, NULL);
}

LassoIdWsf2DiscoServiceContext*
lasso_idwsf2_disco_service_context_new_full(const gchar *serviceType,
		LassoIdWsf2DiscoEndpointContext *endpointContext)
{
	LassoIdWsf2DiscoServiceContext *context;

	context = g_object_new(LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT, NULL);

	context->ServiceType = g_strdup(serviceType);
	context->EndpointContext = g_object_ref(endpointContext);

	return context;
}

