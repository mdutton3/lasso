/* $Id: disco_endpoint_context.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "disco_endpoint_context.h"
#include "./idwsf2_strings.h"
#include "sbf_framework.h"

/**
 * SECTION:disco_endpoint_context
 * @short_description: &lt;disco:EndpointContext&gt;
 *
 * <figure><title>Schema fragment for disco:EndpointContext</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="EndpointContextType">
 *   <xs:sequence>
 *     <xs:element ref="Address"        maxOccurs="unbounded" />
 *     <xs:element ref="sbf:Framework"  maxOccurs="unbounded" />
 *     <xs:element ref="SecurityMechID" maxOccurs="unbounded" />
 *     <xs:element ref="Action"         minOccurs="0"
 *       maxOccurs="unbounded" />
 *     </xs:sequence>
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Address", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoEndpointContext, Address), NULL, NULL, NULL},
	{ "Framework", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoEndpointContext, Framework), NULL, NULL, NULL},
	{ "SecurityMechID", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoEndpointContext, SecurityMechID), NULL, NULL, NULL},
	{ "Action", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoEndpointContext, Action), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2DiscoEndpointContextClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "EndpointContext");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCOVERY_HREF, LASSO_IDWSF2_DISCOVERY_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_endpoint_context_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoEndpointContextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoEndpointContext),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoEndpointContext", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_endpoint_context_new:
 *
 * Creates a new #LassoIdWsf2DiscoEndpointContext object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoEndpointContext object
 **/
LassoIdWsf2DiscoEndpointContext*
lasso_idwsf2_disco_endpoint_context_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT, NULL);
}


LassoIdWsf2DiscoEndpointContext*
lasso_idwsf2_disco_endpoint_context_new_full(const gchar *address)
{
	LassoIdWsf2DiscoEndpointContext *context;

	context = lasso_idwsf2_disco_endpoint_context_new();

	context->Address = g_list_append(NULL, g_strdup(address));
	context->Framework = g_list_append(NULL, lasso_idwsf2_sbf_framework_new_full("2.0"));

	return context;
}
