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

#include <lasso/environs/server.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_server_add_provider_from_file(LassoServer *server,
				    gchar       *filename)
{
  LassoProvider *provider;
  
  provider = lasso_provider_new_from_filename(filename);
  g_ptr_array_add(server->providers, provider);
  
  return (1);
}

LassoProvider*
lasso_server_get_provider(LassoServer *server,
			  gchar       *providerID)
{
  LassoProvider *provider;
  char *id;
  int index, len;
  
  len = server->providers->len;
  for(index = 0; index<len; index++) {
    provider = g_ptr_array_index(server->providers, index);
    
    id = lasso_provider_get_providerID(provider);
    if (!strcmp(providerID, id)) {
      return(provider);
    }
  }
  
  return(NULL);
}

gint
lasso_server_set_security(gchar *private_key,
			  gchar *public_key,
			  gchar *certificate)
{
  g_return_if_fail(private_key);
  g_return_if_fail(public_key);
  g_return_if_fail(certificate);

}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_server_instance_init(LassoServer *server)
{
  server->providers = g_ptr_array_new();

  server->public_key  = NULL;
  server->private_key = NULL;
  server->certificate = NULL;
}

static void
lasso_server_class_init(LassoServerClass *klass) {
}

GType lasso_server_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoServerClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_server_class_init,
      NULL,
      NULL,
      sizeof(LassoServer),
      0,
      (GInstanceInitFunc) lasso_server_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoServer",
				       &this_info, 0);
  }
  return this_type;
}

LassoServer *
lasso_server_new(const gchar *public_key,
		 const gchar *private_key,
		 const gchar *certificate)
{
  LassoServer *server;

  server = LASSO_SERVER(g_object_new(LASSO_TYPE_SERVER, NULL));

  server->public_key  = public_key;
  server->private_key = private_key;
  server->certificate = certificate;

  return(server);
}
