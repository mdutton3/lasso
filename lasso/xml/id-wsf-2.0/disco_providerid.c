/* $Id: disco_providerid.c 2183 2005-01-22 15:57:56 dlaniel $ 
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

#include <lasso/xml/id-wsf-2.0/disco_providerid.h>

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "content", SNIPPET_TEXT_CHILD, G_STRUCT_OFFSET(LassoIdWsf2DiscoProviderID, content) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DiscoProviderID *node)
{
	node->content = NULL;
}

static void
class_init(LassoIdWsf2DiscoProviderIDClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "ProviderID");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_DISCO_HREF,
			LASSO_IDWSF2_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_disco_providerid_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2DiscoProviderIDClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DiscoProviderID),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2DiscoProviderID", &this_info, 0);
	}
	return this_type;
}

LassoIdWsf2DiscoProviderID*
lasso_idwsf2_disco_providerid_new()
{
	return LASSO_IDWSF2_DISCO_PROVIDERID(g_object_new(
		LASSO_TYPE_IDWSF2_DISCO_PROVIDERID, NULL));
}

LassoIdWsf2DiscoProviderID*
lasso_idwsf2_disco_providerid_new_with_content(gchar *content)
{
	LassoIdWsf2DiscoProviderID *idwsf2_disco_providerid = LASSO_IDWSF2_DISCO_PROVIDERID(
		g_object_new(LASSO_TYPE_IDWSF2_DISCO_PROVIDERID, NULL));
	
	idwsf2_disco_providerid->content = g_strdup(content);

	return idwsf2_disco_providerid;
}
