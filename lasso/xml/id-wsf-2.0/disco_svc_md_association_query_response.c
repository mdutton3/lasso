/* $Id: disco_svc_md_association_query_response.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "disco_svc_md_association_query_response.h"
#include "idwsf2_strings.h"

/**
 * SECTION:disco_svc_md_association_query_response
 * @short_description: &lt;disco:SvcMDAssociationQueryResponse&gt;
 *
 * <figure><title>Schema fragment for disco:SvcMDAssociationQueryResponse</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="SvcMDAssociationQueryResponseType">
 *   <xs:sequence>
 *     <xs:element ref="lu:Status" />
 *     <xs:element ref="SvcMDID" minOccurs="0" maxOccurs="unbounded" />
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Status", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDAssociationQueryResponse, Status),
		"LassoIdWsf2UtilStatus", LASSO_IDWSF2_UTIL_PREFIX, LASSO_IDWSF2_UTIL_HREF},
	{ "SvcMDID", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDAssociationQueryResponse, SvcMDID), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDAssociationQueryResponse, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DiscoSvcMDAssociationQueryResponse *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SvcMDAssociationQueryResponse");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCOVERY_HREF, LASSO_IDWSF2_DISCOVERY_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_svc_md_association_query_response_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoSvcMDAssociationQueryResponseClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoSvcMDAssociationQueryResponse),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoSvcMDAssociationQueryResponse", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_svc_md_association_query_response_new:
 *
 * Creates a new #LassoIdWsf2DiscoSvcMDAssociationQueryResponse object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoSvcMDAssociationQueryResponse object
 **/
LassoIdWsf2DiscoSvcMDAssociationQueryResponse*
lasso_idwsf2_disco_svc_md_association_query_response_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE, NULL);
}
