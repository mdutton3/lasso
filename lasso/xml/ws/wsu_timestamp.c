/* $Id: wsu_timestamp.c 2495 2005-05-02 09:17:08Z dlaniel $
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

#include <lasso/xml/ws/wsu_timestamp.h>

/*
 *
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Created", SNIPPET_NODE, G_STRUCT_OFFSET(LassoWsuTimestamp, Created) },
	{ "Expired", SNIPPET_NODE, G_STRUCT_OFFSET(LassoWsuTimestamp, Expired) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsuTimestamp *node)
{
	node->Created = NULL;
	node->Expired = NULL;
}

static void
class_init(LassoWsuTimestampClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Timestamp");
	lasso_node_class_set_ns(nclass, LASSO_WSU_HREF, LASSO_WSU_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsu_timestamp_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsuTimestampClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsuTimestamp),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsuTimestamp", &this_info, 0);
	}
	return this_type;
}

LassoWsuTimestamp*
lasso_wsu_timestamp_new()
{
	LassoWsuTimestamp *node;

	node = g_object_new(LASSO_TYPE_WSU_TIMESTAMP, NULL);

	return node;
}
