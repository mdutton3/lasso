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

#include <lasso/xml/disco_query_response.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-1.0-errata-v1.0.xsd):
 *
 * <xs:element name="QueryResponse" type="QueryResponseType"/>
 * <xs:complexType name="QueryResponseType">
 *   <xs:sequence>
 *     <xs:element ref="Status"/>
 *     <xs:element ref="ResourceOffering" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="Credentials" minOccurs="0">
 *       <xs:complexType>
 *         <xs:sequence>
 *           <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *         </xs:sequence>
 *       </xs:complexType>
 *     </xs:element>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE,
	  G_STRUCT_OFFSET(LassoDiscoQueryResponse, Status) },
	{ "ResourceOffering", SNIPPET_LIST_NODES,
	  G_STRUCT_OFFSET(LassoDiscoQueryResponse, ResourceOffering) },
	{ "Credentials", SNIPPET_NODE,
	  G_STRUCT_OFFSET(LassoDiscoQueryResponse, Credentials) },
	{ "id", SNIPPET_ATTRIBUTE,
	  G_STRUCT_OFFSET(LassoDiscoQueryResponse, id) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoQueryResponse *node)
{
	node->Status = NULL;
	node->ResourceOffering = NULL;
	node->Credentials = NULL;
	
	node->id = NULL;
}

static void
class_init(LassoDiscoQueryResponseClass *class)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(class);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "QueryResponse");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_query_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoQueryResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoQueryResponse),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoQueryResponse", &this_info, 0);
	}
	return this_type;
}

LassoDiscoQueryResponse*
lasso_disco_query_response_new(LassoUtilityStatus *status)
{
	LassoDiscoQueryResponse *node;

	g_return_val_if_fail(LASSO_IS_UTILITY_STATUS(status), NULL);

	node = g_object_new(LASSO_TYPE_DISCO_QUERY_RESPONSE, NULL);

	node->Status = status;

	return node;
}
