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

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_user_add_assertion(LassoUser *user,
			 gchar     *remote_providerID,
			 LassoNode *assertion)
{
  gchar *providerId;
  int i;
  gboolean found;

  /* add the remote provider id */
  found = FALSE;
  for(i = 0; i<user->assertion_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->assertion_providerIDs, i)))
      found = TRUE;
  }
  if(found==FALSE){
    g_ptr_array_add(user->assertion_providerIDs, g_strdup(remote_providerID));
  }

  /* add the assertion */
  g_hash_table_insert(user->assertions, g_strdup(remote_providerID), assertion);
}

void
lasso_user_add_identity(LassoUser     *user,
			gchar         *remote_providerID,
			LassoIdentity *identity)
{
  g_hash_table_insert(user->identities, g_strdup(remote_providerID), identity);
}

static void
lasso_user_dump_assertion(gpointer   key,
			  gpointer   value,
			  LassoNode *assertions)
{
  LassoNode      *assertion;
  LassoNodeClass *assertion_class, *assertions_class;

  /* a new lasso assertion dump node */
  assertion = lasso_node_new();
  assertion_class = LASSO_NODE_GET_CLASS(assertion);
  assertion_class->set_name(assertion, LASSO_USER_ASSERTION_NODE);

  /* set the remote provider id */
  assertion_class->set_prop(assertion, LASSO_USER_REMOTE_PROVIDERID_NODE, value);
  
  /* add the liberty alliance assertion node */
  assertions_class = LASSO_NODE_GET_CLASS(assertions);

  /* add the lasso assertion node in lasso assertions node */
  assertion_class->add_child(assertions, assertion, FALSE);
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

gchar*
lasso_user_dump(LassoUser *user)
{
  LassoNode      *user_node, *assertions_node, *identities_node;
  LassoNodeClass *user_class, *assertions_class, *identities_class;

  user_node = lasso_node_new();
  user_class = LASSO_NODE_GET_CLASS(user_node);
  user_class->set_name(user_node, LASSO_USER_NODE);

  /* dump the assertions */
  assertions_node = lasso_node_new();
  assertions_class = LASSO_NODE_GET_CLASS(assertions_node);
  assertions_class->set_name(assertions_node, LASSO_USER_ASSERTIONS_NODE);
  g_hash_table_foreach(user->assertions, lasso_user_dump_assertion, assertions_node);
  user_class->add_child(user_node, assertions_node, FALSE);

  /* dump the identities */
  identities_node = lasso_node_new();
  identities_class = LASSO_NODE_GET_CLASS(identities_node);
  identities_class->set_name(identities_node, LASSO_USER_IDENTITIES_NODE);
  g_hash_table_foreach(user->identities, lasso_user_dump_identity, identities_node);
  user_class->add_child(user_node, identities_node, FALSE);

  return(lasso_node_export(user_node));
}

LassoNode*
lasso_user_get_assertion(LassoUser *user,
			 gchar     *remote_providerID)
{
  return(g_hash_table_lookup(user->assertions, remote_providerID));
}

gchar*
lasso_user_get_next_providerID(LassoUser *user)
{
  return(g_ptr_array_index(user->assertion_providerIDs, 0));
}

LassoIdentity*
lasso_user_get_identity(LassoUser *user,
			gchar     *remote_providerID)
{
  return(g_hash_table_lookup(user->identities, remote_providerID));
}

void
lasso_user_remove_assertion(LassoUser     *user,
			    gchar         *remote_providerID)
{
  LassoNode *assertion;
  int i;

  /* remove the assertion */
  assertion = lasso_user_get_assertion(user->assertions, remote_providerID);
  g_hash_table_steal(user->assertions, remote_providerID);

  /* remove the remote provider id */
  for(i = 0; i<user->assertion_providerIDs->len; i++){
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(user->assertion_providerIDs, i))){
      g_ptr_array_remove_index(user->assertion_providerIDs, i);
      break;
    }
  }
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_user_instance_init(LassoUser *user)
{
  user->assertion_providerIDs = g_ptr_array_new();
  user->identities = g_hash_table_new(g_str_hash,  g_str_equal);
  user->assertions = g_hash_table_new(g_str_hash,  g_str_equal);
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
  LassoNode      *user_node, *identities_node, *assertions_node, *assertion_node, *local_nameIdentifier, *remote_nameIdentifier;
  LassoNodeClass *identities_class, *assertions_class;
  LassoIdentity  *identity;
  xmlNodePtr     identities_xmlNode, identity_xmlNode, assertions_xmlNode, assertion_xmlNode, nameIdentifier_xmlNode;
  LassoUser      *user;
  xmlChar        *remote_providerID;

  /* new object */
  user = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  /* get user */
  debug(DEBUG, "LassoUser node\n");
  user_node = lasso_node_new_from_dump(dump);

  /* get assertions */
  assertions_node = lasso_node_get_child(user_node, LASSO_USER_ASSERTIONS_NODE, NULL);
  if(assertions_node){
    debug(DEBUG, "LassoAssertions node found\n");
    assertions_class = LASSO_NODE_GET_CLASS(assertions_node);    
    assertions_xmlNode = assertions_class->get_xmlNode(assertions_node);
    assertion_xmlNode = assertions_xmlNode->children;
    while(assertion_xmlNode){
      /* get only element node with name LassoAssertion */
      if(assertion_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(assertion_xmlNode->name, LASSO_USER_ASSERTION_NODE)){
	debug(DEBUG, "LassoAssertion found\n");
	remote_providerID = xmlGetProp(assertion_xmlNode, LASSO_USER_REMOTE_PROVIDERID_NODE);
	assertion_node = lasso_node_new_from_xmlNode(assertion_xmlNode);
	lasso_user_add_assertion(user, remote_providerID, assertion_node);
      }
      assertion_xmlNode = assertion_xmlNode->next;
    }
  }

  /* set lasso identities */
  identities_node = lasso_node_get_child(user_node, LASSO_USER_IDENTITIES_NODE, NULL);
  identities_class = LASSO_NODE_GET_CLASS(identities_node);
  identities_xmlNode = identities_class->get_xmlNode(identities_node);
  if(identities_xmlNode){
    /* get the identities */
    debug(DEBUG, "LassoIdentities node found\n");
    identity_xmlNode = identities_xmlNode->children;
    while(identity_xmlNode){
      if(identity_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(identity_xmlNode->name, LASSO_USER_IDENTITY_NODE)){
	/* a new identity */
	debug(DEBUG, "LassoIdentity found\n");
	identity = lasso_identity_new(xmlGetProp(identity_xmlNode, LASSO_USER_REMOTE_PROVIDERID_NODE));
	nameIdentifier_xmlNode = identity_xmlNode->children;
	while(nameIdentifier_xmlNode){
	  if(nameIdentifier_xmlNode->type==XML_ELEMENT_NODE){
	    if(xmlStrEqual(nameIdentifier_xmlNode->name, LASSO_IDENTITY_LOCAL_NAME_IDENTIFIER_NODE)){
	      /* a new local name identifier */
	      debug(DEBUG, "LassoLocalNameIdentifier found\n");
	      local_nameIdentifier = lasso_node_new_from_xmlNode(nameIdentifier_xmlNode);
	      lasso_identity_set_local_nameIdentifier(identity, local_nameIdentifier);
	    }
	    else if(xmlStrEqual(nameIdentifier_xmlNode->name, LASSO_IDENTITY_REMOTE_NAME_IDENTIFIER_NODE)){
	      /* a new remote name identifier */
	      debug(DEBUG, "LassoRemoteNameIdentifier found\n");
	      remote_nameIdentifier = lasso_node_new_from_xmlNode(nameIdentifier_xmlNode);
	      lasso_identity_set_local_nameIdentifier(identity, remote_nameIdentifier);

	    } /* end if */

	  } /* end if */

	  nameIdentifier_xmlNode = nameIdentifier_xmlNode->next;
	} /* end while */

      }

      identity_xmlNode = identity_xmlNode->next;
    } /* end while */

  }

  return(user);
}
