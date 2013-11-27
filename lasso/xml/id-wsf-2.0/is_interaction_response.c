/* $Id: is_interaction_response.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "is_interaction_response.h"
#include "idwsf2_strings.h"

/**
 * SECTION:is_interaction_response
 * @short_description: &lt;is:InteractionResponse&gt;
 *
 * <figure><title>Schema fragment for is:InteractionResponse</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="InteractionResponseType">
 *   <xs:sequence>
 *     <xs:element ref="lu:Status"/>
 *     <xs:choice>
 *       <xs:element name="InteractionStatement" type="InteractionStatementType"
 *         minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element name="Parameter" type="ParameterType" minOccurs="0" maxOccurs="unbounded"/>
 *       </xs:choice>
 *     </xs:sequence>
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionResponse, Status),
		"LassoIdWsf2UtilStatus", LASSO_IDWSF2_UTIL_PREFIX, LASSO_IDWSF2_UTIL_HREF},
	{ "InteractionStatement", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionResponse, InteractionStatement), NULL, NULL, NULL},
	{ "Parameter", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionResponse, Parameter), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2IsInteractionResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "InteractionResponse");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_IS_HREF, LASSO_IDWSF2_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_is_interaction_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2IsInteractionResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2IsInteractionResponse),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2IsInteractionResponse", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_is_interaction_response_new:
 *
 * Creates a new #LassoIdWsf2IsInteractionResponse object.
 *
 * Return value: a newly created #LassoIdWsf2IsInteractionResponse object
 **/
LassoIdWsf2IsInteractionResponse*
lasso_idwsf2_is_interaction_response_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_IS_INTERACTION_RESPONSE, NULL);
}
