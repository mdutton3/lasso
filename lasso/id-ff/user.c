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

static void
lasso_user_node_identity_add(xmlChar *key, LassoIdentity *identity, LassoNode *userNode)
{
  LassoNode *node, *child;
  LassoNodeClass *class;

  /* set the Identity node */
/*   node = lasso_node_new(); */
/*   class = LASSO_NODE_GET_CLASS(LASSO_NODE(node)); */
/*   class->set_name(LASSO_NODE(node), "Identity"); */

  /* add the remote provider id */
/*   class->new_child(node, "RemoteProviderID", key, FALSE); */

  /* add the local name identifier */
/*   child = lasso_node_new(); */
/*   class = LASSO_NODE_GET_CLASS(LASSO_NODE(node)); */
/*   class->set_name(LASSO_NODE(node), "LocalNameIdentifier"); */
/*   class->lasso_node_add_child(child, identity->local_nameIdentifier); */
/*   class->lasso_node_add_child(node, child); */
  
  /* add the remote provider id */
/*   child = lasso_node_new(); */
/*   class = LASSO_NODE_GET_CLASS(LASSO_NODE(node)); */
/*   class->set_name(LASSO_NODE(node), "RemoteNameIdentifier"); */
/*   lasso_node_add_child(child, identity->remote_nameIdentifier); */
/*   lasso_node_add_child(node, child); */

  /* add the identity node to the user node */
/*   lasso_node_add_child(userNode, identity); */
}

xmlChar *
lasso_user_export(LassoUser *user)
{
  LassoNode *user_node, *identities, *assertions, *assertion_artifacts;
  LassoNodeClass *class;

  /* set the user node  */
  user_node = lasso_node_new();
  class = LASSO_NODE_GET_CLASS(LASSO_NODE(user_node));
  class->set_name(LASSO_NODE(user_node), "User");

  /* insert all of the identity of the user */
  g_hash_table_foreach(user->identities, lasso_user_node_identity_add, user);
  
  return(lasso_node_export(user));
}

void
lasso_user_add_assertion(LassoUser *user,
			 xmlChar   *remote_providerID,
			 LassoNode *assertion)
{
  g_hash_table_insert(user->assertions, remote_providerID, assertion);
}

LassoNode *
lasso_user_get_assertion(LassoUser *user,
			 xmlChar   *nameIdentifier)
{
  return(g_hash_table_lookup(user->assertions, nameIdentifier));
}

void
lasso_user_store_response(LassoUser     *user,
			  xmlChar       *assertionArtifact,
			  LassoResponse *response)
{
  g_hash_table_insert(user->assertion_artifacts,
		      g_strdup(assertionArtifact),
		      lasso_node_copy(LASSO_NODE(response)));
}

LassoNode *lasso_user_get_assertionArtifact(LassoUser *user,
					    xmlChar   *artifact)
{
  LassoNode *assertion;

  assertion = g_hash_table_lookup(user->assertion_artifacts, artifact);
  if(assertion){
    g_hash_table_steal(user->assertion_artifacts, artifact);
  }

  return(assertion);
}

void
lasso_user_add_identity(LassoUser     *user,
			xmlChar       *remote_providerID,
			LassoIdentity *identity)
{
  g_hash_table_insert(user->identities, remote_providerID, identity);
}

LassoIdentity*
lasso_user_get_identity(LassoUser *user,
			xmlChar   *remote_providerID)
{
  return(g_hash_table_lookup(user->identities, remote_providerID));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_user_instance_init(LassoUser *user)
{
  user->identities = g_hash_table_new(g_str_hash,  g_str_equal);
  user->assertions = g_hash_table_new(g_str_hash,  g_str_equal);
  user->assertion_artifacts = g_hash_table_new(g_str_hash,  g_str_equal);
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
lasso_user_new(xmlChar *user_str)
{
  LassoUser *user;

  user = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  if(user_str){
    /* parse the user str */
  }

  return(user);
}
