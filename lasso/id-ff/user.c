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
lasso_user_dump_assertion(gpointer   key,
			  gpointer   value,
			  LassoNode *assertions)
{

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

xmlChar *
lasso_user_dump(LassoUser *user)
{
  LassoNode      *user_node, *assertions_node, *identities_node;
  LassoNodeClass *user_class, *assertions_class, *identities_class;

  user_node = lasso_node_new();
  user_class = LASSO_NODE_GET_CLASS(user_node);
  user_class->set_name(user_node, "User");

  /* dump the assertions */
  assertions_node = lasso_node_new();
  assertions_class = LASSO_NODE_GET_CLASS(assertions_node);
  assertions_class->set_name(assertions_node, "Assertions");
  g_hash_table_foreach(user->assertions, lasso_user_dump_assertion, assertions_node);
  user_class->add_child(user_node, assertions_node, FALSE);

  /* dump the identities */
  identities_node = lasso_node_new();
  identities_class = LASSO_NODE_GET_CLASS(identities_node);
  identities_class->set_name(identities_node, "Identities");
  g_hash_table_foreach(user->identities, lasso_user_dump_identity, identities_node);
  user_class->add_child(user_node, identities_node, FALSE);

  return(lasso_node_export(user_node));
}

void
lasso_user_add_assertion(LassoUser *user,
			 xmlChar   *remote_providerID,
			 LassoNode *assertion)
{
  g_hash_table_insert(user->assertions, g_strdup(remote_providerID), assertion);
}

LassoNode *
lasso_user_get_assertion(LassoUser *user,
			 xmlChar   *remote_providerID)
{
  return(g_hash_table_lookup(user->assertions, remote_providerID));
}


void
lasso_user_add_identity(LassoUser     *user,
			xmlChar       *remote_providerID,
			LassoIdentity *identity)
{
  g_hash_table_insert(user->identities, g_strdup(remote_providerID), identity);
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
lasso_user_new_from_dump(xmlChar *dump)
{
  LassoNode      *user_node, *identities_node;
  LassoNodeClass *identities_class;
  LassoIdentity  *identity;
  xmlNodePtr      xmlNode;
  LassoUser      *user;
  xmlChar        *remote_providerID;

  /* new object */
  user = LASSO_USER(g_object_new(LASSO_TYPE_USER, NULL));

  /* get node from dump */
  user_node = lasso_node_new_from_dump(dump);

  /* get the assertions */

  /* set the identities */
  identities_node = lasso_node_get_child(user_node, "Identities", NULL);
  identities_class = LASSO_NODE_GET_CLASS(identities_node);
  xmlNode = identities_class->get_xmlNode(identities_node);
  if(xmlNode){
    xmlNode = xmlNode->children;
    while(xmlNode){
      if(xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(xmlNode->name, "Identity")){
	identity = lasso_identity_new(xmlGetProp(xmlNode, "RemoteProviderID"));
	lasso_identity_set_local_nameIdentifier(user, identity);
	xmlNode = xmlNode->next;
      }
    }
  }

  return(user);
}
