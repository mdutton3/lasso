/* $Id: dstref_sort.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $ 
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

#include "dstref_sort.h"

/*
 * Schema fragment (liberty-idwsf-dst-ref-v2.1.xsd):
 *
 * <xs:complexType name="SortType">
 *   <xs:simpleContent>
 *     <xs:extension base="xs:string"/>
 *   </xs:simpleContent>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "content", SNIPPET_TEXT_CHILD,
		G_STRUCT_OFFSET(LassoIdWsf2DstRefSort, content) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DstRefSort *node)
{
	node->content = NULL;
}

static void
class_init(LassoIdWsf2DstRefSortClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Sort");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DSTREF_HREF, LASSO_IDWSF2_DSTREF_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_dstref_sort_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DstRefSortClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DstRefSort),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DstRefSort", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_dstref_sort_new:
 *
 * Creates a new #LassoIdWsf2DstRefSort object.
 *
 * Return value: a newly created #LassoIdWsf2DstRefSort object
 **/
LassoNode*
lasso_idwsf2_dstref_sort_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_DSTREF_SORT, NULL);
}


/**
 * lasso_idwsf2_dstref_sort_new_with_string:
 * @content: 
 *
 * Creates a new #LassoIdWsf2DstRefSort object and initializes it
 * with @content.
 *
 * Return value: a newly created #LassoIdWsf2DstRefSort object
 **/
LassoNode*
lasso_idwsf2_dstref_sort_new_with_string(char *content)
{
	LassoIdWsf2DstRefSort *object;
	object = g_object_new(LASSO_TYPE_IDWSF2_DSTREF_SORT, NULL);
	object->content = g_strdup(content);
	return LASSO_NODE(object);
}
