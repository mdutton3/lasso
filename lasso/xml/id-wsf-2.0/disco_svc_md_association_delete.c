/* $Id: disco_svc_md_association_delete.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#include "disco_svc_md_association_delete.h"

/*
 * Schema fragment (liberty-idwsf-disco-svc-v2.0.xsd):
 *
 * <xs:complexType name="SvcMDAssociationDeleteType">
 *   <xs:sequence>
 *     <xs:element ref="SvcMDID" maxOccurs="unbounded" />
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "SvcMDID", SNIPPET_LIST_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDAssociationDelete, SvcMDID) },
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2DiscoSvcMDAssociationDelete, attributes) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DiscoSvcMDAssociationDelete *node)
{
	node->SvcMDID = NULL;
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2DiscoSvcMDAssociationDeleteClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "SvcMDAssociationDelete");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF, LASSO_IDWSF2_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_svc_md_association_delete_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoSvcMDAssociationDeleteClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoSvcMDAssociationDelete),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoSvcMDAssociationDelete", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_disco_svc_md_association_delete_new:
 *
 * Creates a new #LassoIdWsf2DiscoSvcMDAssociationDelete object.
 *
 * Return value: a newly created #LassoIdWsf2DiscoSvcMDAssociationDelete object
 **/
LassoIdWsf2DiscoSvcMDAssociationDelete*
lasso_idwsf2_disco_svc_md_association_delete_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_DELETE, NULL);
}
