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
#include <lasso/id-ff/sessionprivate.h>

struct _LassoSessionPrivate
{
	gboolean dispose_has_run;
	GList *providerIDs;
	GHashTable *status; /* hold temporary response status for sso-art */
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_session_add_assertion:
 * @session: a #LassoSession
 * @providerID: the provider ID
 * @assertion: the assertion
 *
 * Adds @assertion to the principal session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
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

/**
 * lasso_session_add_status:
 * @session: a #LassoSession
 * @providerID: the provider ID
 * @status: the status
 *
 * Adds @status to the principal session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_add_status(LassoSession *session, char *providerID, LassoSamlpStatus *status)
{
	g_return_val_if_fail(session != NULL, -1);
	g_return_val_if_fail(providerID != NULL, -2);
	g_return_val_if_fail(status != NULL, -3);

	g_hash_table_insert(session->private_data->status, g_strdup(providerID), status);

	session->is_dirty = TRUE;

	return 0;
}



/**
 * lasso_session_get_assertion
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Gets the assertion for the given @providerID.
 *
 * Return value: the assertion or NULL if it didn't exist.  This
 *      #LassoSamlAssertion is internally allocated and must not be freed by
 *      the caller.
 **/
LassoSamlAssertion*
lasso_session_get_assertion(LassoSession *session, gchar *providerID)
{
	return g_hash_table_lookup(session->assertions, providerID);
}

/**
 * lasso_session_get_status
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Gets the status for the given @providerID.
 *
 * Return value: the status or NULL if it didn't exist.  This #LassoSamlpStatus
 *      is internally allocated and must not be freed by the caller.
 **/
LassoSamlpStatus*
lasso_session_get_status(LassoSession *session, gchar *providerID)
{
	return g_hash_table_lookup(session->private_data->status, providerID);
}

static void
add_providerID(gchar *key, LassoLibAssertion *assertion, LassoSession *session)
{
	session->private_data->providerIDs = g_list_append(
			session->private_data->providerIDs, key);
}

/**
 * lasso_session_get_provider_index:
 * @session: a #LassoSession
 * @index: index of requested provider
 *
 * Looks up and returns the nth provider id.
 *
 * Return value: the provider id; or NULL if there were no nth provider.  This
 *      string must be freed by the caller.
 **/
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

/**
 * lasso_session_is_empty:
 * @session: a #LassoSession
 *
 * Returns %TRUE if session is empty.
 *
 * Return value: %TRUE if empty
 **/
gboolean
lasso_session_is_empty(LassoSession *session)
{
	if (session == NULL) return TRUE;

	if (g_hash_table_size(session->assertions))
		return FALSE;
	if (g_hash_table_size(session->private_data->status))
		return FALSE;

	return TRUE;
}

/**
 * lasso_session_remove_assertion:
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Removes assertion for @providerID from @session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_remove_assertion(LassoSession *session, gchar *providerID)
{
	if (g_hash_table_remove(session->assertions, providerID)) {
		session->is_dirty = TRUE;
		return 0;
	}

	return LASSO_ERROR_UNDEFINED; /* assertion not found */
}

/**
 * lasso_session_remove_status:
 * @session: a #LassoSession
 * @providerID: the provider ID
 *
 * Removes status for @providerID from @session.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_session_remove_status(LassoSession *session, gchar *providerID)
{
	if (g_hash_table_remove(session->private_data->status, providerID)) {
		session->is_dirty = TRUE;
		return 0;
	}

	return LASSO_ERROR_UNDEFINED; /* status not found */
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
	xmlAddChild(t, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

static void
add_status_childnode(gchar *key, LassoSamlpStatus *value, xmlNode *xmlnode)
{
	xmlNode *t;
	t = xmlNewTextChild(xmlnode, NULL, "Status", NULL);
	xmlSetProp(t, "RemoteProviderID", key);
	xmlAddChild(t, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoSession *session = LASSO_SESSION(node);

	xmlnode = xmlNewNode(NULL, "Session");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, "Version", "2");

	if (g_hash_table_size(session->assertions))
		g_hash_table_foreach(session->assertions,
				(GHFunc)add_assertion_childnode, xmlnode);
	if (g_hash_table_size(session->private_data->status))
		g_hash_table_foreach(session->private_data->status,
				(GHFunc)add_status_childnode, xmlnode);

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
				g_hash_table_insert(session->assertions,
						xmlGetProp(t, "RemoteProviderID"), assertion);
			}
		}
		if (strcmp(t->name, "Status") == 0) {
			n = t->children;
			while (n && n->type != XML_ELEMENT_NODE) n = n->next;
			
			if (n) {
				LassoSamlpStatus *status;
				status = LASSO_SAMLP_STATUS(lasso_node_new_from_xmlNode(n));
				g_hash_table_insert(session->private_data->status,
						xmlGetProp(t, "RemoteProviderID"), status);
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
	session->private_data->status = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_node_destroy);

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

/**
 * lasso_session_new:
 *
 * Creates a new #LassoSession.
 *
 * Return value: a newly created #LassoSession
 **/
LassoSession*
lasso_session_new()
{
	return g_object_new(LASSO_TYPE_SESSION, NULL);
}

/**
 * lasso_session_new_from_dump:
 * @dump: XML server dump
 *
 * Restores the @dump to a new #LassoSession.
 *
 * Return value: a newly created #LassoSession; or NULL if an error occured
 **/
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

/**
 * lasso_session_dump:
 * @session: a #LassoSession
 *
 * Dumps @session content to an XML string.
 *
 * Return value: the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_session_dump(LassoSession *session)
{
	if (lasso_session_is_empty(session))
		return g_strdup("");

	return lasso_node_dump(LASSO_NODE(session), NULL, 1);
}

/**
 * lasso_session_destroy:
 * @session: a #LassoSession
 *
 * Destroys a session.
 **/
void lasso_session_destroy(LassoSession *session)
{
	lasso_node_destroy(LASSO_NODE(session));
}
