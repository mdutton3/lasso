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

#include <lasso/id-ff/session.h>

struct _LassoSessionPrivate
{
	gboolean dispose_has_run;
	GList *providerIDs;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_session_add_assertion(LassoSession *session, char *providerID, LassoSamlAssertion *assertion)
{
	g_return_val_if_fail(session != NULL, -1);
	g_return_val_if_fail(providerID != NULL, -2);
	g_return_val_if_fail(assertion != NULL, -3);

	g_hash_table_insert(session->assertions, g_strdup(providerID), assertion);

	session->is_dirty = TRUE;

	return 0;
}

LassoSamlAssertion*
lasso_session_get_assertion(LassoSession *session, gchar *providerID)
{
	return g_hash_table_lookup(session->assertions, providerID);
}

gchar*
lasso_session_get_authentication_method(LassoSession *session, gchar *remote_providerID)
{
	/* XXX: somewhere in
	 * session/Assertion[remote_providerID]/AuthenticationStatement
	 */

	g_assert_not_reached();
	return NULL;
}

gchar*
lasso_session_get_first_providerID(LassoSession *session)
{
	return lasso_session_get_provider_index(session, 0);
}

static void
add_providerID(gchar *key, LassoLibAssertion *assertion, LassoSession *session)
{
	session->private_data->providerIDs = g_list_append(
			session->private_data->providerIDs, key);
}

gchar*
lasso_session_get_provider_index(LassoSession *session, gint index)
{
	GList *element;
	int length;

	length = g_hash_table_size(session->assertions);

	if (length == 0)
		return NULL;

	if (session->private_data->providerIDs == NULL ||
			g_list_length(session->private_data->providerIDs) != length)
		g_hash_table_foreach(session->assertions, (GHFunc)add_providerID, session);

	element = g_list_nth(session->private_data->providerIDs, index);
	if (element == NULL)
		return NULL;

	return g_strdup(element->data);
}

gint
lasso_session_remove_assertion(LassoSession *session, gchar *providerID)
{
	if (g_hash_table_remove(session->assertions, providerID)) {
		session->is_dirty = TRUE;
		return 0;
	}

	return LASSO_ERROR_UNDEFINED; /* assertion not found */
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
add_assertion_childnode(gchar *key, LassoLibAssertion *value, xmlNode *xmlnode)
{
	xmlNode *t;
	t = xmlNewTextChild(xmlnode, NULL, "Assertion", NULL);
	xmlSetProp(t, "RemoteProviderID", key);
	xmlAddChild(t, lasso_node_get_xmlNode(LASSO_NODE(value)));
}

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoSession *session = LASSO_SESSION(node);

	xmlnode = xmlNewNode(NULL, "Session");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, "Version", "2");

	if (g_hash_table_size(session->assertions))
		g_hash_table_foreach(session->assertions,
				(GHFunc)add_assertion_childnode, xmlnode);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoSession *session = LASSO_SESSION(node);
	xmlNode *t, *n;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		if (strcmp(t->name, "Assertion") == 0) {
			n = t->children;
			while (n && n->type != XML_ELEMENT_NODE) n = n->next;
			
			if (n) {
				LassoLibAssertion *assertion;
				assertion = LASSO_LIB_ASSERTION(lasso_node_new_from_xmlNode(n));
				g_hash_table_insert(
						session->assertions,
						xmlGetProp(t, "RemoteProviderID"),
						assertion);
			}
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
	LassoSession *session = LASSO_SESSION(object);

	if (session->private_data->dispose_has_run == TRUE) {
		return;
	}
	session->private_data->dispose_has_run = TRUE;

	debug("Session object 0x%p disposed ...", session);

	/* XXX: here or not ?
	g_hash_table_destroy(session->assertions);
	session->assertions = NULL;
	*/

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoSession *session = LASSO_SESSION(object);

	debug("Session object 0x%p finalized ...", session);

	g_free(session->private_data);
	session->private_data = NULL;

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSession *session)
{
	session->private_data = g_new (LassoSessionPrivate, 1);
	session->private_data->dispose_has_run = FALSE;
	session->private_data->providerIDs = NULL;

	session->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_node_destroy);
	session->is_dirty = FALSE;
}

static void
class_init(LassoSessionClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_session_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSessionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSession),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSession", &this_info, 0);
	}
	return this_type;
}

LassoSession*
lasso_session_new()
{
	return g_object_new(LASSO_TYPE_SESSION, NULL);
}

LassoSession*
lasso_session_new_from_dump(const gchar *dump)
{
	LassoSession *session;
	xmlDoc *doc;

	session = lasso_session_new();
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(session), xmlDocGetRootElement(doc));
	xmlFreeDoc(doc);

	return session;
}

gchar*
lasso_session_dump(LassoSession *session)
{
	if (g_hash_table_size(session->assertions) == 0)
		return g_strdup("");

	return lasso_node_dump(LASSO_NODE(session), NULL, 1);
}


void lasso_session_destroy(LassoSession *session)
{
	lasso_node_destroy(LASSO_NODE(session));
}
