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

LassoIdentity *lasso_user_environ_find_identity(LassoUserEnviron *user, char *peer_providerID){
     LassoIdentity *identity;
     int index;

     printf("nb identity %d\n", user->identities->len);
     for(index = 0; index<user->identities->len; index++){
	  identity = g_ptr_array_index(user->identities, index);
	  printf("provider id : %s\n", identity->peer_providerID);
	  if(!strcmp(identity->peer_providerID, peer_providerID)){
	       return(identity);
	  }
     }
     
     return(NULL);
}

int lasso_user_environ_add_assertion(){

}

int lasso_user_environ_add_identity(LassoUserEnviron *user, LassoIdentity *identity){
     g_ptr_array_add(user->identities, identity);

     return(1);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_user_environ_instance_init(LassoUserEnviron *user){
     user->identities = g_ptr_array_new();
     user->assertions = g_ptr_array_new();
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
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
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

  return(user);
}
