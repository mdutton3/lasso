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
lasso_server_add_provider(LassoServer *server,
			  gchar       *metadata,
			  const gchar *public_key,
			  const gchar *certificate)
{
  LassoProvider *provider;
  
  provider = lasso_provider_new(metadata, public_key, certificate);
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

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_server_instance_init(LassoServer *server)
{
  server->providers = g_ptr_array_new();

  server->private_key = NULL;
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
    
    this_type = g_type_register_static(LASSO_TYPE_PROVIDER,
				       "LassoServer",
				       &this_info, 0);
  }
  return this_type;
}

LassoServer *
lasso_server_new(const gchar *metadata,
		 const gchar *public_key,
		 const gchar *private_key,
		 const gchar *certificate,
		 guint        signature_method)
{
  LassoServer *server;
  xmlDocPtr  doc;
  xmlNodePtr root;

  server = LASSO_SERVER(g_object_new(LASSO_TYPE_SERVER, NULL));

  LASSO_PROVIDER(server)->public_key  = public_key;
  LASSO_PROVIDER(server)->certificate = certificate;
  server->private_key = private_key;
  server->signature_method = signature_method;

  doc = xmlParseFile(metadata);
  root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
  xmlFreeDoc(doc);
  //LASSO_PROVIDER(server)->metadata = lasso_node_new();
  //LASSO_NODE_CLASS(LASSO_PROVIDER(server)->metadata)->set_xmlNode(LASSO_PROVIDER(server)->metadata, root); 
  LASSO_PROVIDER(server)->metadata = lasso_node_new_from_xmlNode(root);

  return(server);
}
