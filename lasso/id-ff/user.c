/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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
#define LASSO_USER_REMOTE_PROVIDERID_NODE "RemoteProviderID"

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_user_add_assertion(LassoUser *user,
			 gchar     *remote_providerID,
			 LassoNode *assertion)
{
  gchar *providerId;
  int i;
  gboolean found;

  g_return_val_if_fail(user!=NULL, -1);
  g_return_val_if_fail(remote_providerID!=NULL, -2);
  g_return_val_if_fail(assertion!=NULL, -3);

  /* add the remote provider id */
  found = FALSE;
  for(i = 0; i<user->assertion_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->assertion_providerIDs, i)))
      found = TRUE;
  }
  if(found==TRUE){
    debug(ERROR, "A provider id already exists\n");
    return(-4);
  }

  debug(DEBUG, "add provider id %s\n", remote_providerID);
  g_ptr_array_add(user->assertion_providerIDs, g_strdup(remote_providerID));

  /* add the assertion */
  debug(DEBUG, "Add an assertion for %s\n", remote_providerID);
  g_hash_table_insert(user->assertions, g_strdup(remote_providerID), assertion);

  return(0);
}

gint
lasso_user_add_identity(LassoUser     *user,
			gchar         *remote_providerID,
			LassoIdentity *identity)
{
  g_return_val_if_fail(user!=NULL, -1);
  g_return_val_if_fail(remote_providerID!=NULL, -2);
  g_return_val_if_fail(identity!=NULL, -3);

  debug(DEBUG, "Add an identity for %s\n", remote_providerID);
  g_hash_table_insert(user->identities, g_strdup(remote_providerID), identity);

  return(0);
}

static void
lasso_user_dump_assertion(gpointer   key,
			  gpointer   value,
			  LassoNode *assertions)
{
  LassoNode      *assertion_node;
  LassoNodeClass *assertion_class, *assertions_class;

  debug(DEBUG, "key : %s, value : %s\n", key, lasso_node_export(value));

  /* new lasso assertion node */
  assertion_node = lasso_node_new();
  assertion_class = LASSO_NODE_GET_CLASS(assertion_node);
  assertion_class->set_name(assertion_node, LASSO_USER_ASSERTION_NODE);

  /* set the remote provider id */
  assertion_class->set_prop(assertion_node, LASSO_USER_REMOTE_PROVIDERID_NODE, key);
  
  /* set assertion node */
  assertion_class->add_child(assertion_node, value, FALSE);

  /* add lasso assertion node to lasso assertions node */
  assertions_class = LASSO_NODE_GET_CLASS(assertions);
  assertions_class->add_child(assertions, assertion_node, TRUE);
}

static void
lasso_user_dump_identity(gpointer   key,
			 gpointer   value,
			 LassoNode *identities)
{
  LassoNode      *identity_node;
  LassoNodeClass *identity_class;
  xmlChar        *dump;

  dump = lasso_identity_dump(value);
  identity_node = lasso_node_new_from_dump(dump);
  identity_class = LASSO_NODE_GET_CLASS(identity_node);
  identity_class->add_child(identities, identity_node, TRUE);
}

void
lasso_user_destroy(LassoUser *user)
{

}

gchar*
lasso_user_dump(LassoUser *user)
{
  LassoNode      *user_node, *assertions_node, *identities_node;
  LassoNodeClass *user_class, *assertions_class, *identities_class;
  int table_size;

  g_return_val_if_fail(user!=NULL, NULL);

  user_node = lasso_node_new();
  user_class = LASSO_NODE_GET_CLASS(user_node);
  user_class->set_name(user_node, LASSO_USER_NODE);

  /* dump the assertions */
  table_size = g_hash_table_size(user->assertions);
  if(table_size>0){
    debug(INFO, "Dump assertions\n");
    assertions_node = lasso_node_new();
    assertions_class = LASSO_NODE_GET_CLASS(assertions_node);
    assertions_class->set_name(assertions_node, LASSO_USER_ASSERTIONS_NODE);
    g_hash_table_foreach(user->assertions, lasso_user_dump_assertion, assertions_node);
    user_class->add_child(user_node, assertions_node, FALSE);
  }
  
  /* dump the identities */
  table_size = g_hash_table_size(user->identities);
  if(table_size>0){
    debug(INFO, "Dump identities\n");
    identities_node = lasso_node_new();
    identities_class = LASSO_NODE_GET_CLASS(identities_node);
    identities_class->set_name(identities_node, LASSO_USER_IDENTITIES_NODE);
    g_hash_table_foreach(user->identities, lasso_user_dump_identity, identities_node);
    user_class->add_child(user_node, identities_node, FALSE);
  }

  return(lasso_node_export(user_node));
}

LassoNode*
lasso_user_get_assertion(LassoUser *user,
			 gchar     *remote_providerID)
{
  g_return_val_if_fail(user!=NULL, NULL);
  g_return_val_if_fail(remote_providerID!=NULL, NULL);
  return(g_hash_table_lookup(user->assertions, remote_providerID));
}

gchar*
lasso_user_get_next_providerID(LassoUser *user)
{
  gchar *remote_providerID;

  g_return_val_if_fail(user!=NULL, NULL);

  if(user->assertion_providerIDs->len==0)
    return(NULL);

  remote_providerID = g_strdup(g_ptr_array_index(user->assertion_providerIDs, 0));

  return(remote_providerID);
}

LassoIdentity*
lasso_user_get_identity(LassoUser *user,
			gchar     *remote_providerID)
{
  g_return_val_if_fail(user!=NULL, NULL);
  g_return_val_if_fail(remote_providerID!=NULL, NULL);

  return(g_hash_table_lookup(user->identities, remote_providerID));
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
  g_hash_table_steal(user->assertions, remote_providerID);

  /* remove the remote provider id */
  for(i = 0; i<user->assertion_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->assertion_providerIDs, i))){
      debug(DEBUG, "Remove assertion of %s\n", remote_providerID);
      g_ptr_array_remove_index(user->assertion_providerIDs, i);
      break;
    }
  }

  return(0);
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_user_instance_init(LassoUser *user)
{
  user->assertion_providerIDs = g_ptr_array_new();
  user->identities = g_hash_table_new(g_str_hash, g_str_equal);
  user->assertions = g_hash_table_new(g_str_hash, g_str_equal);
}

static void
lasso_user_class_init(LassoUserClass *klass)
{

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

  g_return_val_if_fail(dump != NULL, NULL);

  /* new object */
  user = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  /* get user */
  user_node = lasso_node_new_from_dump(dump);
  if (user_node == NULL) {
    debug(WARNING, "Can't create a user from dump.\n");
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
	remote_providerID = lasso_node_get_attr_value(assertion_node, LASSO_USER_REMOTE_PROVIDERID_NODE);
	lasso_user_add_assertion(user, remote_providerID, lasso_node_copy(assertion_node));
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
	remote_providerID = lasso_node_get_attr_value(identity_node, LASSO_IDENTITY_REMOTE_PROVIDERID_NODE);

	/* new identity */
	identity = lasso_identity_new(remote_providerID);

	/* local name identifier */
	local_nameIdentifier_node = lasso_node_get_child(identity_node, LASSO_IDENTITY_LOCAL_NAME_IDENTIFIER_NODE, NULL);
	if (local_nameIdentifier_node != NULL) {
	  nameIdentifier_node = lasso_node_get_child(local_nameIdentifier_node, "NameIdentifier", NULL);
	  lasso_identity_set_local_nameIdentifier(identity, lasso_node_copy(nameIdentifier_node));
	  lasso_node_destroy(nameIdentifier_node);
	  lasso_node_destroy(local_nameIdentifier_node);
	}

	/* remote name identifier */
	remote_nameIdentifier_node = lasso_node_get_child(identity_node, LASSO_IDENTITY_REMOTE_NAME_IDENTIFIER_NODE, NULL);
	if (remote_nameIdentifier_node != NULL) {
	  nameIdentifier_node = lasso_node_get_child(remote_nameIdentifier_node, "NameIdentifier", NULL);
	  lasso_identity_set_remote_nameIdentifier(identity, lasso_node_copy(nameIdentifier_node));
	  lasso_node_destroy(nameIdentifier_node);
	  lasso_node_destroy(remote_nameIdentifier_node);
	}

	lasso_user_add_identity(user, remote_providerID, identity);

	g_free(remote_providerID);
	lasso_node_destroy(identity_node);
      }

      identity_xmlNode = identity_xmlNode->next;
    }

    lasso_node_destroy(identities_node);
  }

  lasso_node_destroy(user_node);

  return (user);
}
