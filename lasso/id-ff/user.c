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

#include <lasso/environs/user.h>

#define LASSO_USER_NODE                   "LassoUser"
#define LASSO_USER_IDENTITIES_NODE        "LassoIdentities"
#define LASSO_USER_IDENTITY_NODE          "LassoIdentity"
#define LASSO_USER_ASSERTIONS_NODE        "LassoAssertions"
#define LASSO_USER_ASSERTION_NODE         "LassoAssertion"
#define LASSO_USER_REMOTE_PROVIDERID_ATTR "RemoteProviderID"

struct _LassoUserPrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* private functions                                                         */
/*****************************************************************************/

static void
lasso_user_copy_assertion(gpointer key,
			  gpointer value,
			  gpointer assertions)
{
  g_hash_table_insert((GHashTable *)assertions, g_strdup((gchar *)key),
		      lasso_node_copy(LASSO_NODE(value)));
}

static void
lasso_user_copy_identity(gpointer key,
			 gpointer value,
			 gpointer identities)
{
  g_hash_table_insert((GHashTable *)identities, g_strdup((gchar *)key),
		      lasso_identity_copy(LASSO_IDENTITY(value)));
}

static void
lasso_user_dump_assertion(gpointer   key,
			  gpointer   value,
			  LassoNode *assertions)
{
  LassoNode      *assertion_node, *assertion_copy;
  LassoNodeClass *assertion_class, *assertions_class;

  /* new lasso assertion node */
  assertion_node = lasso_node_new();
  assertion_class = LASSO_NODE_GET_CLASS(assertion_node);
  assertion_class->set_name(assertion_node, LASSO_USER_ASSERTION_NODE);

  /* set the remote provider id */
  assertion_class->set_prop(assertion_node, LASSO_USER_REMOTE_PROVIDERID_ATTR, key);
  
  /* set assertion node */
  assertion_copy = lasso_node_copy(LASSO_NODE(value));
  assertion_class->add_child(assertion_node, assertion_copy, FALSE);
  lasso_node_destroy(assertion_copy);

  /* add lasso assertion node to lasso assertions node */
  assertions_class = LASSO_NODE_GET_CLASS(assertions);
  assertions_class->add_child(assertions, assertion_node, TRUE);
  lasso_node_destroy(assertion_node);
}

static void
lasso_user_dump_identity(gpointer   key,
			 gpointer   value,
			 LassoNode *identities)
{
  LassoNode      *identity_node;
  LassoNodeClass *identity_class;
  xmlChar        *dump;

  dump = lasso_identity_dump(LASSO_IDENTITY(value));
  identity_node = lasso_node_new_from_dump(dump);
  xmlFree(dump);
  identity_class = LASSO_NODE_GET_CLASS(identity_node);
  identity_class->add_child(identities, identity_node, TRUE);
  lasso_node_destroy(identity_node);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_user_add_assertion(LassoUser *user,
			 gchar     *remote_providerID,
			 LassoNode *assertion)
{
  int i;
  gboolean found;

  g_return_val_if_fail(user!=NULL, -1);
  g_return_val_if_fail(remote_providerID!=NULL, -2);
  g_return_val_if_fail(assertion!=NULL, -3);

  /* add the remote provider id */
  found = FALSE;
  for(i = 0; i<user->assertion_providerIDs->len; i++) {
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->assertion_providerIDs, i)))
      found = TRUE;
  }
  if(found == TRUE){
    message(G_LOG_LEVEL_ERROR, "A provider id already exists\n");
    return(-4);
  }

  g_ptr_array_add(user->assertion_providerIDs, g_strdup(remote_providerID));

  /* add the assertion */
  g_hash_table_insert(user->assertions, g_strdup(remote_providerID),
		      lasso_node_copy(assertion));

  return(0);
}

gint
lasso_user_add_identity(LassoUser     *user,
			gchar         *remote_providerID,
			LassoIdentity *identity)
{
  LassoIdentity *old_identity;
  gboolean found;
  int i;

  g_return_val_if_fail(user != NULL, -1);
  g_return_val_if_fail(remote_providerID != NULL, -2);
  g_return_val_if_fail(identity != NULL, -3);

  /* add the remote provider id if not already saved */
  found = FALSE;
  for(i = 0; i<user->identity_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->identity_providerIDs, i)))
      found = TRUE;
  }
  if(found == FALSE){
    g_ptr_array_add(user->identity_providerIDs, g_strdup(remote_providerID));
  }  

  /* add the identity, replace if one already exists */
  old_identity = lasso_user_get_identity(user, remote_providerID);
  if (old_identity != NULL) {
    lasso_user_remove_identity(user, remote_providerID);
    /* BEWARE: Don't destroy old_identity here.
       It's not a copy. But it must change */
  }
  g_hash_table_insert(user->identities, g_strdup(remote_providerID), identity);

  return(0);
}

LassoUser*
lasso_user_copy(LassoUser *user)
{
  LassoUser *copy;
  guint i;

  if (user == NULL) {
    return(NULL);
  }

  copy = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  copy->assertion_providerIDs = g_ptr_array_new();
  for(i=0; i<user->assertion_providerIDs->len; i++) {
    g_ptr_array_add(copy->assertion_providerIDs,
		    g_strdup(g_ptr_array_index(user->assertion_providerIDs, i)));
  }
  copy->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
					   (GDestroyNotify)g_free,
					   (GDestroyNotify)lasso_node_destroy);
  g_hash_table_foreach(copy->assertions, (GHFunc)lasso_user_copy_assertion,
		       (gpointer)copy->assertions);

  copy->identity_providerIDs = g_ptr_array_new();
  for(i=0; i<user->identity_providerIDs->len; i++) {
    g_ptr_array_add(copy->identity_providerIDs,
		    g_strdup(g_ptr_array_index(user->identity_providerIDs, i)));
  }
  copy->identities = g_hash_table_new_full(g_str_hash, g_str_equal,
					   (GDestroyNotify)g_free,
					   (GDestroyNotify)lasso_node_destroy);
  g_hash_table_foreach(copy->identities, (GHFunc)lasso_user_copy_identity,
		       (gpointer)copy->identities);

  return(copy);
}

void
lasso_user_destroy(LassoUser *user)
{
  if (LASSO_IS_USER(user)) {
    g_object_unref(G_OBJECT(user));
  }
}

gchar*
lasso_user_dump(LassoUser *user)
{
  LassoNode      *user_node, *assertions_node, *identities_node;
  LassoNodeClass *user_class, *assertions_class, *identities_class;
  int table_size;
  xmlChar *dump;

  g_return_val_if_fail(user != NULL, NULL);

  user_node = lasso_node_new();
  user_class = LASSO_NODE_GET_CLASS(user_node);
  user_class->set_name(user_node, LASSO_USER_NODE);

  /* dump the assertions */
  table_size = g_hash_table_size(user->assertions);
  if (table_size > 0) {
    assertions_node = lasso_node_new();
    assertions_class = LASSO_NODE_GET_CLASS(assertions_node);
    assertions_class->set_name(assertions_node, LASSO_USER_ASSERTIONS_NODE);
    g_hash_table_foreach(user->assertions, (GHFunc)lasso_user_dump_assertion, assertions_node);
    user_class->add_child(user_node, assertions_node, FALSE);
    lasso_node_destroy(assertions_node);
  }
  
  /* dump the identities */
  table_size = g_hash_table_size(user->identities);
  if (table_size > 0) {
    identities_node = lasso_node_new();
    identities_class = LASSO_NODE_GET_CLASS(identities_node);
    identities_class->set_name(identities_node, LASSO_USER_IDENTITIES_NODE);
    g_hash_table_foreach(user->identities, (GHFunc)lasso_user_dump_identity, identities_node);
    user_class->add_child(user_node, identities_node, FALSE);
    lasso_node_destroy(identities_node);
  }

  dump = lasso_node_export(user_node);

  lasso_node_destroy(user_node);

  return(dump);
}

LassoNode*
lasso_user_get_assertion(LassoUser *user,
			 gchar     *remote_providerID)
{
  LassoNode *assertion;

  g_return_val_if_fail(user != NULL, NULL);
  g_return_val_if_fail(remote_providerID != NULL, NULL);

  assertion = (LassoNode *)g_hash_table_lookup(user->assertions,
					       remote_providerID);
  if (assertion == NULL)
	  return NULL;

  return(lasso_node_copy(assertion));
}

gchar*
lasso_user_get_authentication_method(LassoUser *user,
				     gchar     *remote_providerID)
{
  LassoNode *assertion, *as;
  gchar *providerID = remote_providerID;
  gchar *authentication_method;
  GError *err = NULL;

  if (remote_providerID == NULL) {
    providerID = lasso_user_get_next_assertion_remote_providerID(user);
  }
  assertion = lasso_user_get_assertion(user, providerID);
  if (remote_providerID == NULL) {
    g_free(providerID);
  }
  as = lasso_node_get_child(assertion, "AuthenticationStatement", NULL);
  authentication_method = lasso_node_get_attr_value(as, "AuthenticationMethod", &err);
  if (authentication_method == NULL) {
    message(G_LOG_LEVEL_ERROR, err->message);
    g_error_free(err);
    goto done;
  }

 done:
  lasso_node_destroy(assertion);
  lasso_node_destroy(as);
  return (authentication_method);
}

LassoIdentity*
lasso_user_get_identity(LassoUser *user,
			gchar     *remote_providerID)
{
  g_return_val_if_fail(user!=NULL, NULL);
  g_return_val_if_fail(remote_providerID!=NULL, NULL);

  LassoIdentity *id;

  id = (LassoIdentity *)g_hash_table_lookup(user->identities,
					    remote_providerID);
  if (id == NULL) {
    debug("No Identity found with remote ProviderID = %s\n", remote_providerID);
  }

  /* FIXME: identity should be a copy (fix lasso_user_add_identity too) */
  return(id);
}

gchar*
lasso_user_get_next_assertion_remote_providerID(LassoUser *user)
{
  gchar *remote_providerID;

  g_return_val_if_fail(user!=NULL, NULL);

  if(user->assertion_providerIDs->len == 0) {
    return(NULL);
  }

  remote_providerID = g_strdup(g_ptr_array_index(user->assertion_providerIDs, 0));

  return(remote_providerID);
}

gchar*
lasso_user_get_next_identity_remote_providerID(LassoUser *user)
{
  gchar *remote_providerID;

  g_return_val_if_fail(user!=NULL, NULL);

  if(user->identity_providerIDs->len == 0) {
    return(NULL);
  }

  remote_providerID = g_strdup(g_ptr_array_index(user->identity_providerIDs, 0));

  return(remote_providerID);
}

gint
lasso_user_remove_assertion(LassoUser     *user,
			    gchar         *remote_providerID)
{
  LassoNode *assertion;
  int i;

  g_return_val_if_fail(user!=NULL, -1);

  g_return_val_if_fail(remote_providerID!=NULL, -2);

  /* remove the assertion */
  assertion = lasso_user_get_assertion(user, remote_providerID);
  if (assertion != NULL) {
    g_hash_table_remove(user->assertions, remote_providerID);
    lasso_node_destroy(assertion);
  }

  /* remove the remote provider id */
  for(i = 0; i<user->assertion_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->assertion_providerIDs, i))){
      g_ptr_array_remove_index(user->assertion_providerIDs, i);
      break;
    }
  }

  return(0);
}

gint
lasso_user_remove_identity(LassoUser *user,
			   gchar     *remote_providerID)
{
  LassoIdentity *identity;
  int i;

  g_return_val_if_fail(user!=NULL, -1);
  g_return_val_if_fail(remote_providerID!=NULL, -2);

  /* remove the identity */
  identity = lasso_user_get_identity(user, remote_providerID);
  if (identity != NULL) {
    g_hash_table_remove(user->identities, remote_providerID);
  }
  else {
    debug("Failed to remove identity for remote Provider %s\n", remote_providerID);
  }

  /* remove the identity remote provider id */
  for(i = 0; i<user->identity_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->identity_providerIDs, i))){
      debug("Remove identity of %s\n", remote_providerID);
      g_ptr_array_remove_index(user->identity_providerIDs, i);
      break;
    }
  }

  return(0);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_user_dispose(LassoUser *user)
{
  if (user->private->dispose_has_run == TRUE) {
    return;
  }
  user->private->dispose_has_run = TRUE;

  debug("User object 0x%x disposed ...\n", user);

  g_hash_table_destroy(user->assertions);
  user->assertions = NULL;
  g_hash_table_destroy(user->identities);
  user->identities = NULL;

  parent_class->dispose(G_OBJECT(user));
}

static void
lasso_user_finalize(LassoUser *user)
{
  gint i;

  debug("User object 0x%x finalized ...\n", user);

  /* free allocated memory for assertion_providerIDs array */
  for (i=0; i<user->assertion_providerIDs->len; i++) {
    g_free(user->assertion_providerIDs->pdata[i]);
    user->assertion_providerIDs->pdata[i] = NULL;
  }
  g_ptr_array_free(user->assertion_providerIDs, TRUE);
  user->assertion_providerIDs = NULL;

  /* free allocated memory for identity_providerIDs array */
  for (i=0; i<user->identity_providerIDs->len; i++) {
    g_free(user->identity_providerIDs->pdata[i]);
    user->identity_providerIDs->pdata[i] = NULL;
  }
  g_ptr_array_free(user->identity_providerIDs, TRUE);
  user->identity_providerIDs = NULL;

  g_free(user->private);
  user->private = NULL;

  parent_class->finalize(G_OBJECT(user));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_user_instance_init(LassoUser *user)
{
  user->private = g_new (LassoUserPrivate, 1);
  user->private->dispose_has_run = FALSE;

  user->assertion_providerIDs = g_ptr_array_new();
  user->assertions = g_hash_table_new_full(g_str_hash, g_str_equal,
					   (GDestroyNotify)g_free,
					   (GDestroyNotify)lasso_node_destroy);

  user->identity_providerIDs = g_ptr_array_new();
  user->identities = g_hash_table_new_full(g_str_hash, g_str_equal,
					   (GDestroyNotify)g_free,
					   (GDestroyNotify)lasso_identity_destroy);
}

static void
lasso_user_class_init(LassoUserClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_user_dispose;
  gobject_class->finalize = (void *)lasso_user_finalize;
}

GType lasso_user_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoUserClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_user_class_init,
      NULL,
      NULL,
      sizeof(LassoUser),
      0,
      (GInstanceInitFunc) lasso_user_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoUser",
				       &this_info, 0);
  }
  return this_type;
}

LassoUser*
lasso_user_new()
{
  LassoUser *user;

  user = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  return(user);
}

LassoUser*
lasso_user_new_from_dump(gchar *dump)
{
  LassoNode      *user_node;
  LassoNode      *assertions_node, *assertion_node;
  LassoNode      *identities_node, *identity_node;
  LassoNode      *nameIdentifier_node, *local_nameIdentifier_node, *remote_nameIdentifier_node;

  LassoNodeClass *identities_class, *assertions_class;

  xmlNodePtr     identities_xmlNode, identity_xmlNode, assertions_xmlNode, assertion_xmlNode;

  LassoUser      *user;

  LassoIdentity  *identity;

  xmlChar        *remote_providerID;

  GError         *err = NULL;

  g_return_val_if_fail(dump != NULL, NULL);

  /* new object */
  user = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  /* get user */
  user_node = lasso_node_new_from_dump(dump);
  if (user_node == NULL) {
    message(G_LOG_LEVEL_WARNING, "Can't create a user from dump\n");
    return (NULL);
  }

  /* get assertions */
  assertions_node = lasso_node_get_child(user_node, LASSO_USER_ASSERTIONS_NODE, NULL);
  if (assertions_node != NULL) {
    assertions_class = LASSO_NODE_GET_CLASS(assertions_node);
    assertions_xmlNode = assertions_class->get_xmlNode(assertions_node);
    assertion_xmlNode = assertions_xmlNode->children;

    while (assertion_xmlNode != NULL) {
      /* assertion xmlNode  */
      if (assertion_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(assertion_xmlNode->name, LASSO_USER_ASSERTION_NODE)) {
	/* assertion node */
	assertion_node = lasso_node_new_from_xmlNode(assertion_xmlNode);
	remote_providerID = lasso_node_get_attr_value(assertion_node, LASSO_USER_REMOTE_PROVIDERID_ATTR, &err);
	if (remote_providerID == NULL) {
	  message(G_LOG_LEVEL_ERROR, err->message);
	  g_error_free(err);
	  continue;
	}
	lasso_user_add_assertion(user, remote_providerID, assertion_node);
	g_free(remote_providerID);
	lasso_node_destroy(assertion_node);
      }

      assertion_xmlNode = assertion_xmlNode->next;
    }
  }
  lasso_node_destroy(assertions_node);

  /* identities*/
  identities_node = lasso_node_get_child(user_node, LASSO_USER_IDENTITIES_NODE, NULL);
  if (identities_node != NULL) {
    identities_class = LASSO_NODE_GET_CLASS(identities_node);
    identities_xmlNode = identities_class->get_xmlNode(identities_node);
    identity_xmlNode = identities_xmlNode->children;

    while (identity_xmlNode != NULL) {
      if (identity_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(identity_xmlNode->name, LASSO_USER_IDENTITY_NODE)) {
	identity_node = lasso_node_new_from_xmlNode(identity_xmlNode);
	remote_providerID = lasso_node_get_attr_value(identity_node, LASSO_IDENTITY_REMOTE_PROVIDERID_NODE, NULL);
	/* new identity */
	identity = lasso_identity_new(remote_providerID);

	/* local name identifier */
	local_nameIdentifier_node = lasso_node_get_child(identity_node, LASSO_IDENTITY_LOCAL_NAME_IDENTIFIER_NODE, NULL);
	if (local_nameIdentifier_node != NULL) {
	  nameIdentifier_node = lasso_node_get_child(local_nameIdentifier_node, "NameIdentifier", NULL);
	  lasso_identity_set_local_nameIdentifier(identity, nameIdentifier_node);
	  debug("  ... add local name identifier %s\n", lasso_node_get_content(nameIdentifier_node));
	  lasso_node_destroy(nameIdentifier_node);
	  lasso_node_destroy(local_nameIdentifier_node);
	}

	/* remote name identifier */
	remote_nameIdentifier_node = lasso_node_get_child(identity_node, LASSO_IDENTITY_REMOTE_NAME_IDENTIFIER_NODE, NULL);
	if (remote_nameIdentifier_node != NULL) {
	  nameIdentifier_node = lasso_node_get_child(remote_nameIdentifier_node, "NameIdentifier", NULL);
	  lasso_identity_set_remote_nameIdentifier(identity, nameIdentifier_node);
	  debug("  ... add remote name identifier %s\n", lasso_node_get_content(nameIdentifier_node));
	  lasso_node_destroy(nameIdentifier_node);
	  lasso_node_destroy(remote_nameIdentifier_node);
	}
	debug("Add identity for %s\n", remote_providerID);
	lasso_user_add_identity(user, remote_providerID, identity);

	xmlFree(remote_providerID);
	lasso_node_destroy(identity_node);
      }

      identity_xmlNode = identity_xmlNode->next;
    }

    lasso_node_destroy(identities_node);
  }

  lasso_node_destroy(user_node);

  return (user);
}
