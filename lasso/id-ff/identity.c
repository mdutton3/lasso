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

#include <lasso/id-ff/identity.h>

struct _LassoIdentityPrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_identity_add_federation(LassoIdentity *identity, LassoFederation *federation)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), -1);
	g_return_val_if_fail(LASSO_IS_FEDERATION(federation), -3);

	/* add the federation, replace if one already exists */
	g_hash_table_insert(identity->federations,
			g_strdup(federation->remote_providerID), federation);
	identity->is_dirty = TRUE;

	return 0;
}

LassoFederation*
lasso_identity_get_federation(LassoIdentity *identity, gchar *providerID)
{
	return g_hash_table_lookup(identity->federations, providerID);
}

gint
lasso_identity_remove_federation(LassoIdentity *identity, char *remote_providerID)
{
	if (g_hash_table_remove(identity->federations, remote_providerID) == FALSE) {
		debug("Failed to remove federation for remote Provider %s", remote_providerID);
		return LASSO_ERROR_UNDEFINED;
	}
	identity->is_dirty = TRUE;
	return 0;
}

void
lasso_identity_destroy(LassoIdentity *identity)
{
	lasso_node_destroy(LASSO_NODE(identity));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
add_federation_childnode(gchar *key, LassoFederation *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value)));
}

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoIdentity *identity = LASSO_IDENTITY(node);

	xmlnode = xmlNewNode(NULL, "Identity");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, "Version", "2");

	if (g_hash_table_size(identity->federations))
		g_hash_table_foreach(identity->federations,
				(GHFunc)add_federation_childnode, xmlnode);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdentity *identity = LASSO_IDENTITY(node);
	xmlNode *t;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		if (strcmp(t->name, "Federation") == 0) {
			LassoFederation *federation;
			federation = LASSO_FEDERATION(lasso_node_new_from_xmlNode(t));
			g_hash_table_insert(
					identity->federations,
					g_strdup(federation->remote_providerID), federation);
		}

		t = t->next;
	}

	return 0;
}


/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoIdentity *identity = LASSO_IDENTITY(object);

	if (identity->private_data->dispose_has_run == TRUE) {
		return;
	}
	identity->private_data->dispose_has_run = TRUE;

	debug("Identity object 0x%p disposed ...", identity);

	/* XXX: here or in finalize ?
	 * g_hash_table_destroy(identity->federations); */

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoIdentity *identity = LASSO_IDENTITY(object);

	debug("Identity object 0x%p finalized ...", identity);
	identity->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdentity *identity)
{
	identity->private_data = g_new(LassoIdentityPrivate, 1);
	identity->private_data->dispose_has_run = FALSE;

	identity->federations = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_federation_destroy);
	identity->is_dirty = FALSE;
}

static void
class_init(LassoIdentityClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_identity_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdentityClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdentity),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdentity", &this_info, 0);
	}
	return this_type;
}

LassoIdentity*
lasso_identity_new()
{
	return g_object_new(LASSO_TYPE_IDENTITY, NULL);
}

LassoIdentity*
lasso_identity_new_from_dump(const gchar *dump)
{
	LassoIdentity *identity;
	xmlDoc *doc;

	identity = lasso_identity_new();
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(identity), xmlDocGetRootElement(doc));
	xmlFreeDoc(doc);

	return identity;
}

gchar*
lasso_identity_dump(LassoIdentity *identity)
{
	if (g_hash_table_size(identity->federations) == 0)
		return g_strdup("");

	return lasso_node_dump(LASSO_NODE(identity), NULL, 1);
}

