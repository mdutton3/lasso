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

#include <lasso/environs/server_environ.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/* add a provider, return the number of providers in the server context */
int lasso_server_environ_add_provider(LassoServerEnviron *env, LassoProvider *provider){
     LassoNodeClass *class;
     
     class = LASSO_NODE_GET_CLASS(env);
     class->add_child(LASSO_NODE(env), LASSO_NODE(provider), TRUE);
     env->nbProviders++;

     return(env->nbProviders);
}

int lasso_server_environ_add_provider_filename(LassoServerEnviron *env, char *filename){
     LassoNodeClass *class;
     LassoProvider *provider;
     int nb;

     provider = lasso_provider_new_metadata_from_filename("./sp.xml");
     nb = lasso_server_environ_add_provider(env, provider);

     return(nb);
}

LassoProvider *lasso_server_environ_get_provider(LassoServerEnviron *env, const char *providerId){
     LassoProvider *provider;
     GPtrArray *children;
     int index, len;

     children = lasso_node_get_children(LASSO_NODE(env));
     len = children->len;
     index = 0;
     while(index<len){
	  provider = (LassoProvider *)g_ptr_array_index(children, index);
	  if(lasso_provider_is_providerId(provider, providerId)){
	       return(provider);
	  }
	  index++;
     }
     
     return(NULL);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_server_environ_instance_init(LassoServerEnviron *env)
{
    LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(env));
    class->set_name(LASSO_NODE(env), "ServerEnviron");

    env->nbProviders = 0;
}

static void
lasso_server_environ_class_init(LassoServerEnvironClass *klass){
}

GType lasso_server_environ_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoServerEnvironClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_server_environ_class_init,
      NULL,
      NULL,
      sizeof(LassoServerEnviron),
      0,
      (GInstanceInitFunc) lasso_server_environ_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoServerEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoServerEnviron *lasso_server_environ_new()
{
  LassoServerEnviron *env;

  env = LASSO_SERVER_ENVIRON(g_object_new(LASSO_TYPE_SERVER_ENVIRON, NULL));

  return(env);

}
