/* $Id: subsref_query.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "subsref_query.h"
#include "idwsf2_strings.h"

/**
 * SECTION:subsref_query
 * @short_description: &lt;subsref:Query&gt;
 *
 * <figure><title>Schema fragment for subsref:Query</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="QueryType">
 *   <xs:complexContent>
 *     <xs:extension base="dst:RequestType">
 *       <xs:sequence>
 *         <xs:element ref="subsref:TestItem" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="subsref:QueryItem" minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="subsref:Subscription" minOccurs="0" maxOccurs="unbounded"/>
 *       </xs:sequence>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "TestItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQuery, TestItem), NULL, NULL, NULL},
	{ "QueryItem", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQuery, QueryItem), NULL, NULL, NULL},
	{ "Subscription", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2SubsRefQuery, Subscription), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2SubsRefQueryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Query");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SUBSREF_HREF, LASSO_IDWSF2_SUBSREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_subsref_query_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2SubsRefQueryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2SubsRefQuery),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_DST_REQUEST,
				"LassoIdWsf2SubsRefQuery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_subsref_query_new:
 *
 * Creates a new #LassoIdWsf2SubsRefQuery object.
 *
 * Return value: a newly created #LassoIdWsf2SubsRefQuery object
 **/
LassoIdWsf2SubsRefQuery*
lasso_idwsf2_subsref_query_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SUBSREF_QUERY, NULL);
}
