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

#include <lasso/environs/session.h>
#include <lasso/lasso_config.h>

#define LASSO_SESSION_NODE                   "Session"
#define LASSO_SESSION_ASSERTIONS_NODE        "Assertions"
#define LASSO_SESSION_ASSERTION_NODE         "AuthnAssertion"
#define LASSO_SESSION_REMOTE_PROVIDERID_ATTR "RemoteProviderID"

struct _LassoSessionPrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* private functions                                                         */
/*****************************************************************************/

static void
lasso_session_copy_assertion(gpointer key,
			     gpointer value,
			     gpointer assertions)
{
  g_hash_table_insert((GHashTable *)assertions, g_strdup((gchar *)key),
		      lasso_node_copy(LASSO_NODE(value)));
}

static void
lasso_session_dump_assertion(gpointer   key,
			     gpointer   value,
			     LassoNode *assertions)
{
  LassoNode      *assertion_node, *assertion_copy;
  LassoNodeClass *assertion_class, *assertions_class;

  /* new lasso assertion node */
  assertion_node = lasso_node_new();
  assertion_class = LASSO_NODE_GET_CLASS(assertion_node);
  assertion_class->set_name(assertion_node, LASSO_SESSION_ASSERTION_NODE);

  /* set the remote provider id */
  assertion_class->set_prop(assertion_node, LASSO_SESSION_REMOTE_PROVIDERID_ATTR, key);
  
  /* set assertion node */
  assertion_copy = lasso_node_copy(LASSO_NODE(value));
  assertion_class->add_child(assertion_node, assertion_copy, FALSE);
  lasso_node_destroy(assertion_copy);

  /* add lasso assertion node to lasso assertions node */
  assertions_class = LASSO_NODE_GET_CLASS(assertions);
  assertions_class->add_child(assertions, assertion_node, TRUE);
  lasso_node_destroy(assertion_node);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_session_add_assertion(LassoSession *session,
			    gchar        *providerID,
			    LassoNode    *assertion)
{
  int i;
  gboolean found = FALSE;

  g_return_val_if_fail(session != NULL, -1);
  g_return_val_if_fail(providerID != NULL, -2);
  g_return_val_if_fail(assertion != NULL, -3);

  /* add the remote provider id */
  for(i = 0; i<session->providerIDs->len; i++) {
    if(xmlStrEqual(providerID, g_ptr_array_index(session->providerIDs, i))) {
      found = TRUE;
      break;
    }
  }
  if(found == TRUE) {
    debug("An assertion existed already for this providerID, it was replaced by the new one.\n");
  }
  else {
    g_ptr_array_add(session->providerIDs, g_strdup(providerID));
  }

  /* add the assertion */
  g_hash_table_insert(session->assertions, g_strdup(providerID),
		      lasso_node_copy(assertion));

  session->is_dirty = TRUE;

  return 0;
}

LassoSession*
lasso_session_copy(LassoSession *session)
{
  LassoSession *copy;
  guint i;

  if (session == NULL) {
    return NULL;
  }

  copy = LASSO_SESSION(g_object_new(LASSO_TYPE_SESSION, NULL));

  copy->providerIDs = g_ptr_array_new();
  for(i=0; i<session->providerIDs->len; i++) {
    g_ptr_array_add(copy->providerIDs,
		    g_strdup(g_ptr_array_index(session->providerIDs, i)));
  }
  copy->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
					   (GDestroyNotify)g_free,
					   (GDestroyNotify)lasso_node_destroy);
  g_hash_table_foreach(session->assertions, (GHFunc)lasso_session_copy_assertion,
		       (gpointer)copy->assertions);
  copy->is_dirty = session->is_dirty;

  return copy;
}

void
lasso_session_destroy(LassoSession *session)
{
  if (LASSO_IS_SESSION(session)) {
    g_object_unref(G_OBJECT(session));
  }
}

gchar*
lasso_session_dump(LassoSession *session)
{
  LassoNode      *session_node, *assertions_node;
  LassoNodeClass *session_class, *assertions_class;
  int             table_size;
  gchar          *dump;

  g_return_val_if_fail(session != NULL, NULL);

  session_node = lasso_node_new();
  session_class = LASSO_NODE_GET_CLASS(session_node);
  session_class->set_name(session_node, LASSO_SESSION_NODE);
  session_class->set_ns(session_node, lassoLassoHRef, NULL);

  /* dump the assertions */
  table_size = g_hash_table_size(session->assertions);
  if (table_size > 0) {
    assertions_node = lasso_node_new();
    assertions_class = LASSO_NODE_GET_CLASS(assertions_node);
    assertions_class->set_name(assertions_node, LASSO_SESSION_ASSERTIONS_NODE);
    g_hash_table_foreach(session->assertions, (GHFunc)lasso_session_dump_assertion,
			 assertions_node);
    session_class->add_child(session_node, assertions_node, FALSE);
    lasso_node_destroy(assertions_node);
  }

  /* Add lasso version in the xml node */
  session_class->set_prop(LASSO_NODE(session_node), "version", PACKAGE_VERSION);

  dump = lasso_node_export(session_node);

  lasso_node_destroy(session_node);

  return dump;
}

LassoNode*
lasso_session_get_assertion(LassoSession *session,
			    gchar        *providerID)
{
  LassoNode *assertion;

  g_return_val_if_fail(session != NULL, NULL);
  g_return_val_if_fail(providerID != NULL, NULL);

  assertion = (LassoNode *)g_hash_table_lookup(session->assertions,
					       providerID);
  if (assertion == NULL) {
    return NULL;
  }

  return lasso_node_copy(assertion);
}

gchar*
lasso_session_get_authentication_method(LassoSession *session,
					gchar        *remote_providerID)
{
  LassoNode *assertion, *as;
  gchar *providerID = remote_providerID;
  gchar *authentication_method;
  GError *err = NULL;

  if (providerID == NULL) {
    providerID = lasso_session_get_first_providerID(session);
  }
  assertion = lasso_session_get_assertion(session, providerID);
  if (providerID == NULL) {
    g_free(providerID);
  }
  as = lasso_node_get_child(assertion, "AuthenticationStatement", NULL, NULL);
  authentication_method = lasso_node_get_attr_value(as, "AuthenticationMethod", &err);
  if (authentication_method == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    g_error_free(err);
    goto done;
  }

 done:
  lasso_node_destroy(as);
  lasso_node_destroy(assertion);
  return authentication_method;
}

gchar*
lasso_session_get_first_providerID(LassoSession *session)
{
  gchar *providerID;

  g_return_val_if_fail(session != NULL, NULL);

  if(session->providerIDs->len == 0) {
    return NULL;
  }

  providerID = g_ptr_array_index(session->providerIDs, 0);
  if (providerID == NULL) {
    return NULL;
  }

  return g_strdup(providerID);
}

gchar*
lasso_session_get_provider_index(LassoSession *session,
				  gint          index)
{
  gchar *providerID;

  g_return_val_if_fail(session != NULL, NULL);

  /* verify index is valid */
  if ((session->providerIDs == NULL) && (session->providerIDs->len < 0)) {
    return NULL;
  }
  if ((index < 0) || (index >= session->providerIDs->len)) {
    return NULL;
  }

  /* get the provider id */
  providerID = g_ptr_array_index(session->providerIDs, index);
  if (providerID == NULL) {
    return NULL;
  }

  return g_strdup(providerID);
}

gint
lasso_session_remove_assertion(LassoSession *session,
			       gchar        *providerID)
{
  LassoNode *assertion;
  int i;

  g_return_val_if_fail(session != NULL, -1);
  g_return_val_if_fail(providerID != NULL, -1);

  /* remove the assertion */
  assertion = lasso_session_get_assertion(session, providerID);
  if (assertion != NULL) {
    g_hash_table_remove(session->assertions, providerID);
    lasso_node_destroy(assertion);
  }

  /* remove the remote provider id */
  for(i = 0; i<session->providerIDs->len; i++) {
    if(xmlStrEqual(providerID, g_ptr_array_index(session->providerIDs, i))) {
      g_ptr_array_remove_index(session->providerIDs, i);
      break;
    }
  }

  session->is_dirty = TRUE;

  return 0;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_session_dispose(LassoSession *session)
{
  if (session->private->dispose_has_run == TRUE) {
    return;
  }
  session->private->dispose_has_run = TRUE;

  debug("Session object 0x%x disposed ...\n", session);

  g_hash_table_destroy(session->assertions);
  session->assertions = NULL;

  parent_class->dispose(G_OBJECT(session));
}

static void
lasso_session_finalize(LassoSession *session)
{
  gint i;

  debug("Session object 0x%x finalized ...\n", session);

  /* free allocated memory for providerIDs array */
  for (i=0; i<session->providerIDs->len; i++) {
    g_free(session->providerIDs->pdata[i]);
    session->providerIDs->pdata[i] = NULL;
  }
  g_ptr_array_free(session->providerIDs, TRUE);
  session->providerIDs = NULL;

  g_free(session->private);
  session->private = NULL;

  parent_class->finalize(G_OBJECT(session));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_session_instance_init(LassoSession *session)
{
  session->private = g_new (LassoSessionPrivate, 1);
  session->private->dispose_has_run = FALSE;

  session->providerIDs = g_ptr_array_new();
  session->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
					      (GDestroyNotify)g_free,
					      (GDestroyNotify)lasso_node_destroy);
  session->is_dirty = TRUE;
}

static void
lasso_session_class_init(LassoSessionClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_session_dispose;
  gobject_class->finalize = (void *)lasso_session_finalize;
}

GType lasso_session_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSessionClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_session_class_init,
      NULL,
      NULL,
      sizeof(LassoSession),
      0,
      (GInstanceInitFunc) lasso_session_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoSession",
				       &this_info, 0);
  }
  return this_type;
}

LassoSession*
lasso_session_new()
{
  LassoSession *session;

  session = LASSO_SESSION(g_object_new(LASSO_TYPE_SESSION, NULL));

  return session;
}

LassoSession*
lasso_session_new_from_dump(gchar *dump)
{
  LassoSession   *session;
  LassoNode      *session_node;
  LassoNode      *assertions_node, *assertion_node, *assertion;
  xmlNodePtr      assertions_xmlNode, assertion_xmlNode;
  xmlChar        *providerID;
  GError         *err = NULL;

  g_return_val_if_fail(dump != NULL, NULL);

  session = LASSO_SESSION(g_object_new(LASSO_TYPE_SESSION, NULL));

  /* get session */
  session_node = lasso_node_new_from_dump(dump);
  if (session_node == NULL) {
    message(G_LOG_LEVEL_WARNING, "Can't create a session from dump\n");
    return NULL;
  }

  /* get assertions */
  assertions_node = lasso_node_get_child(session_node,
					 LASSO_SESSION_ASSERTIONS_NODE,
					 lassoLassoHRef, NULL);
  if (assertions_node != NULL) {
    assertions_xmlNode = LASSO_NODE_GET_CLASS(assertions_node)->get_xmlNode(assertions_node);
    assertion_xmlNode = assertions_xmlNode->children;

    while (assertion_xmlNode != NULL) {
      /* assertion xmlNode  */
      if (assertion_xmlNode->type == XML_ELEMENT_NODE && \
	  xmlStrEqual(assertion_xmlNode->name, LASSO_SESSION_ASSERTION_NODE)) {
	/* assertion node */
	assertion_node = lasso_node_new_from_xmlNode(assertion_xmlNode);
	providerID = lasso_node_get_attr_value(assertion_node,
					       LASSO_SESSION_REMOTE_PROVIDERID_ATTR,
					       &err);
	if (providerID != NULL) {
	  assertion = lasso_node_get_child(assertion_node,
					   "Assertion",
					   NULL, /* lassoLibHRef, FIXME changed for SourceID */
					   &err);
	  if (assertion != NULL) {
	    lasso_session_add_assertion(session, providerID, assertion);
	    lasso_node_destroy(assertion);
	  }
	  else {
	    message(G_LOG_LEVEL_CRITICAL, err->message);
	    g_clear_error(&err);
	  }
	}
	else {
	  message(G_LOG_LEVEL_CRITICAL, err->message);
	  g_clear_error(&err);
	}
	xmlFree(providerID);
	lasso_node_destroy(assertion_node);
      }
      assertion_xmlNode = assertion_xmlNode->next;
    }
  }
  lasso_node_destroy(assertions_node);
  lasso_node_destroy(session_node);

  return session;
}
