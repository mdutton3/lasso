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

xmlChar *
lasso_server_dump(LassoServer *server)
{
  LassoProvider  *provider;
  LassoNode      *server_node, *providers_node;
  LassoNodeClass *server_class, *providers_class;
  xmlChar        *signature_method_str, *dump;
  gint            i;

  server_node = lasso_node_new();
  server_class = LASSO_NODE_GET_CLASS(server_node);
  server_class->set_name(server_node, LASSO_SERVER_NODE);

  /* set private key and signature method */
  if(server->private_key)
    server_class->set_prop(server_node, LASSO_SERVER_PRIVATE_KEY_NODE, server->private_key);

  /* TODO : add the signature method in the dump */

  /* set public key, certificate, metadata */
  provider = LASSO_PROVIDER(server);
  server_class->add_child(server_node, provider->metadata, FALSE);
  if(provider->public_key)
    server_class->set_prop(server_node, LASSO_PROVIDER_PUBLIC_KEY_NODE, provider->public_key);
  if(provider->certificate)
    server_class->set_prop(server_node, LASSO_PROVIDER_CERTIFICATE_NODE, provider->certificate);

  /* set Providers node */
  providers_node = lasso_node_new();
  providers_class = LASSO_NODE_GET_CLASS(providers_node);
  providers_class->set_name(providers_node, LASSO_SERVER_PROVIDERS_NODE);

  /* add providers */
  for(i = 0; i<server->providers->len; i++){
    dump = lasso_provider_dump(g_ptr_array_index(server->providers, i));
    providers_class->add_child(providers_node, lasso_node_new_from_dump(dump), TRUE);
  }

  server_class->add_child(server_node, providers_node, FALSE);

  return(lasso_node_export(server_node));
}

void
lasso_server_add_provider(LassoServer *server,
			  gchar       *metadata,
			  gchar       *public_key,
			  gchar       *certificate)
{
  LassoProvider *provider;

  provider = lasso_provider_new(metadata, public_key, certificate);

  g_ptr_array_add(server->providers, provider);
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
lasso_server_new(gchar *metadata,
		 gchar *public_key,
		 gchar *private_key,
		 gchar *certificate,
		 guint  signature_method)
{
  LassoServer *server;
  xmlDocPtr    doc;
  xmlNodePtr   root;

  server = LASSO_SERVER(g_object_new(LASSO_TYPE_SERVER, NULL));

  LASSO_PROVIDER(server)->public_key  = public_key;
  LASSO_PROVIDER(server)->certificate = certificate;
  server->private_key = private_key;
  server->signature_method = signature_method;

  doc = xmlParseFile(metadata);
  root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
  xmlFreeDoc(doc);
  LASSO_PROVIDER(server)->metadata = lasso_node_new_from_xmlNode(root);

  return(server);
}

LassoServer *
lasso_server_new_from_dump(xmlChar *dump)
{
  LassoNodeClass *server_class, *providers_class;
  LassoNode      *server_node, *providers_node, *metadata;
  LassoServer    *server;
  LassoProvider  *provider;
  xmlNodePtr      xmlNode, providers_xmlNode, provider_xmlNode, entity_xmlNode;
  xmlChar        *content, *public_key, *certificate;

  server = LASSO_SERVER(g_object_new(LASSO_TYPE_SERVER, NULL));

  server_node  = lasso_node_new_from_dump(dump);
  server_class = LASSO_NODE_GET_CLASS(server_node);

  /* set private key and signature method */
  xmlNode = server_class->get_xmlNode(server_node);
  if(xmlNode==NULL){
    return(NULL);
  }

  content = xmlGetProp(xmlNode, LASSO_SERVER_PRIVATE_KEY_NODE);
  if(content){
    server->private_key = content;
  }

  content = xmlGetProp(xmlNode, LASSO_SERVER_SIGNATURE_METHOD_NODE);
  if(content){
    server->signature_method = atoi(content);
  }

  /* set providers */
  providers_node  = lasso_node_get_child(server_node, LASSO_SERVER_PROVIDERS_NODE, NULL);
  providers_class = LASSO_NODE_GET_CLASS(providers_node);
  if(providers_node){
    providers_xmlNode = providers_class->get_xmlNode(providers_node);
    provider_xmlNode = providers_xmlNode->children;
    while(provider_xmlNode){
      /* a provider node, get the public key, certifcate and metadata */
      if(provider_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(provider_xmlNode->name, LASSO_PROVIDER_NODE)){
	/* get the metadata child node */
	entity_xmlNode = provider_xmlNode->children;
	while(entity_xmlNode){
	  if(entity_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(entity_xmlNode->name, "EntityDescriptor"))
	    break;
	  entity_xmlNode = entity_xmlNode->next;
	}
	public_key  = xmlGetProp(provider_xmlNode, LASSO_PROVIDER_PUBLIC_KEY_NODE);
	certificate = xmlGetProp(provider_xmlNode, LASSO_PROVIDER_CERTIFICATE_NODE);
	
	/* add a new provider */
/* 	provider = lasso_provider_new_metadata_xmlNode(metadata); */
/* 	if(public_key){ */
/* 	  lasso_provider_set_public_key(provider, public_key); */
/* 	} */
/* 	if(certificate){ */
/* 	  lasso_provider_set_public_key(provider, certificate); */
/* 	} */
/* 	lasso_server_add_provider(server, provider); */
      }

      provider_xmlNode = provider_xmlNode->next;
    }
  }

  return(server);
}
