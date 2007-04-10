/* $Id: disco_endpoint_context.c 2261 2005-01-27 23:41:05 $ 
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

#include <lasso/xml/id-wsf-2.0/disco_endpoint_context.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-v2.0.xsd):
 * 
 * <xs:element name="EndpointContext" type="EndpointContextType" />
 * <xs:complexType name="EndpointContextType">
 *    <xs:sequence>
 *       <xs:element ref="Address"        maxOccurs="unbounded" />
 *       <xs:element ref="sbf:Framework"  maxOccurs="unbounded" />
 *       <xs:element ref="SecurityMechID" maxOccurs="unbounded" />
 *       <xs:element ref="Action"         minOccurs="0" 
 *                                        maxOccurs="unbounded" />
 *    </xs:sequence>
 * </xs:complexType>
 * 
 * <xs:element name="Address" type="xs:anyURI"/>
 * <xs:element name="Framework" type="sbf:FrameworkType"/>
 * <xs:element name="SecurityMechID" type="xs:anyURI"/>
 * <xs:element name="Action" type="xs:anyURI"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Address", SNIPPET_CONTENT,
	  G_STRUCT_OFFSET(LassoDiscoEndpointContext, Address) },
	{ "Framework", SNIPPET_NODE,
	  G_STRUCT_OFFSET(LassoDiscoEndpointContext, Framework) },
	{ "SecurityMechID", SNIPPET_CONTENT,
	  G_STRUCT_OFFSET(LassoDiscoEndpointContext, SecurityMechID) },
	{ "Action", SNIPPET_CONTENT,
	  G_STRUCT_OFFSET(LassoDiscoEndpointContext, Action) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoEndpointContext *node)
{
	node->Address = NULL;
	node->Framework = NULL;
	node->SecurityMechID = NULL;
	node->Action = NULL;
}

static void
class_init(LassoDiscoEndpointContextClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "EndpointContext");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF, LASSO_IDWSF2_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_endpoint_context_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoEndpointContextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoEndpointContext),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoEndpointContext", &this_info, 0);
	}
	return this_type;
}

LassoDiscoEndpointContext*
lasso_disco_endpoint_context_new(gchar *address)
{
	LassoDiscoEndpointContext *context;

	context = g_object_new(LASSO_TYPE_DISCO_ENDPOINT_CONTEXT, NULL);

	context->Address = g_strdup(address);
	//context->Framework = g_object_ref(lasso_soap_binding_framework_new("2.0"));

	return context;
}
