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

#include <lasso/environs/user_environ.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoIdentity *lasso_user_environ_new_identity(LassoUserEnviron *user, char *peer_providerID){
     LassoIdentity *identity;
     LassoNodeClass *class;

     if(!user->identities){
	  user->identities = lasso_node_new();
	  class = LASSO_NODE_GET_CLASS(LASSO_NODE(user->identities));
	  class->set_name(LASSO_NODE(user->identities), "Identities");
	  class = LASSO_NODE_GET_CLASS(LASSO_NODE(user));
	  class->add_child(LASSO_NODE(user), user->identities, 1); /* !!!! */
     }

     identity = lasso_identity_new(peer_providerID);
     class = LASSO_NODE_GET_CLASS(LASSO_NODE(user->identities));
     class->add_child(LASSO_NODE(user->identities), LASSO_NODE(identity), 1);

     return(identity);
}

LassoIdentity *lasso_user_environ_search_by_alias(LassoUserEnviron *user, char *nameIdentifier){
     LassoNode *identities;
     GPtrArray *children;
     char      *alias_value;
     int        index;

     identities = lasso_node_get_child(LASSO_NODE(user), "Identities", NULL);
     if(!identities)
	  return(NULL);

     children = lasso_node_get_children(identities);
     if(!children)
	  return(NULL);

     index = 0;
     for(index = 0; index<children->len; index++){
	  alias_value = lasso_node_get_attr_value(g_ptr_array_index(children, index), "Alias");
	  printf("alias : %s\n", alias_value);
     }

     return(NULL);
}

LassoIdentity *lasso_user_environ_search_by_name(LassoUserEnviron *user, char *nameIdentifier){
     LassoNode *identities;
     GPtrArray *children;
     char      *alias_value;
     int        index;

     identities = lasso_node_get_child(LASSO_NODE(user), "Identities", NULL);
     if(!identities)
	  return(NULL);

     children = lasso_node_get_children(identities);
     if(!children)
	  return(NULL);

     index = 0;
     for(index = 0; index<children->len; index++){
	  alias_value = lasso_node_get_attr_value(g_ptr_array_index(children, index), "Name");
	  printf("name : %s\n", alias_value);
     }

     return(NULL);
}

LassoIdentity *lasso_user_environ_search_identity(LassoUserEnviron *user, char *peer_providerID){
     LassoNode *userNode, *identity;
     GPtrArray *identities;
     LassoAttr *attr;
     int i = 0;

     if(!user->identities)
	  return(NULL);

     return(NULL);
}

void lasso_user_environ_set_userID(LassoUserEnviron *user, char *userID){
     LassoNodeClass *class = LASSO_NODE_GET_CLASS(user);

     class->new_child(LASSO_NODE(user), "UserID", userID, FALSE);
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_user_environ_instance_init(LassoUserEnviron *user){
    LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(user));
    class->set_name(LASSO_NODE(user), "UserEnviron");
}

static void
lasso_user_environ_class_init(LassoUserEnvironClass *klass) {
}

GType lasso_user_environ_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoUserEnvironClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_user_environ_class_init,
      NULL,
      NULL,
      sizeof(LassoUserEnviron),
      0,
      (GInstanceInitFunc) lasso_user_environ_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoUserEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoUserEnviron*
lasso_user_environ_new()
{
  LassoUserEnviron *user;

  user = LASSO_USER_ENVIRON(g_object_new(LASSO_TYPE_USER_ENVIRON, NULL));

  user->identities = NULL;

  return(user);
}
