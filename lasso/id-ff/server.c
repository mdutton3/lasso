/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#define LASSO_SERVER_NODE                  "LassoServer"
#define LASSO_SERVER_PROVIDERS_NODE        "LassoProviders"
#define LASSO_SERVER_PROVIDERID_NODE       "ProviderID"
#define LASSO_SERVER_PRIVATE_KEY_NODE      "PrivateKey"
#define LASSO_SERVER_CERTIFICATE_NODE      "Certificate"
#define LASSO_SERVER_SIGNATURE_METHOD_NODE "SignatureMethod"

struct _LassoServerPrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static gint
lasso_server_add_lasso_provider(LassoServer   *server,
				LassoProvider *provider)
{
  g_return_val_if_fail(LASSO_IS_SERVER(server), -1);
  g_return_val_if_fail(LASSO_IS_PROVIDER(provider), -2);

  g_ptr_array_add(server->providers, provider);

  return (0);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_server_dump(LassoServer *server)
{
  LassoProvider  *provider;
  LassoNode      *server_node, *providers_node, *provider_node, *metadata_copy;
  LassoNodeClass *server_class, *providers_class;
  xmlChar        *signature_method_str, *dump;
  gint            i;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  server_node = lasso_node_new();
  server_class = LASSO_NODE_GET_CLASS(server_node);
  server_class->set_name(server_node, LASSO_SERVER_NODE);

  /* signature method */
  signature_method_str = g_new(gchar, 6);
  sprintf(signature_method_str, "%d", server->signature_method);
  server_class->set_prop(server_node, LASSO_SERVER_SIGNATURE_METHOD_NODE, signature_method_str);
  g_free(signature_method_str);

  /* providerID */
  if(server->providerID) {
    server_class->set_prop(server_node, LASSO_SERVER_PROVIDERID_NODE, server->providerID);
  }
  /* private key */
  if(server->private_key) {
    server_class->set_prop(server_node, LASSO_SERVER_PRIVATE_KEY_NODE, server->private_key);
  }
  /* certificate */
  if(server->certificate) {
    server_class->set_prop(server_node, LASSO_SERVER_CERTIFICATE_NODE, server->certificate);
  }
  /* metadata */
  provider = LASSO_PROVIDER(server);
  metadata_copy = lasso_node_copy(provider->metadata);
  server_class->add_child(server_node, metadata_copy, FALSE);
  lasso_node_destroy(metadata_copy);
  /* public key */
  if(provider->public_key) {
    server_class->set_prop(server_node, LASSO_PROVIDER_PUBLIC_KEY_NODE, provider->public_key);
  }
  /* ca_certificate */
  if(provider->ca_certificate) {
    server_class->set_prop(server_node, LASSO_PROVIDER_CA_CERTIFICATE_NODE, provider->ca_certificate);
  }
  /* providers */
  providers_node = lasso_node_new();
  providers_class = LASSO_NODE_GET_CLASS(providers_node);
  providers_class->set_name(providers_node, LASSO_SERVER_PROVIDERS_NODE);
  for(i = 0; i<server->providers->len; i++){
    dump = lasso_provider_dump(g_ptr_array_index(server->providers, i));
    provider_node = lasso_node_new_from_dump(dump);
    xmlFree(dump);
    providers_class->add_child(providers_node, provider_node, TRUE);
    lasso_node_destroy(provider_node);
  }
  server_class->add_child(server_node, providers_node, FALSE);
  lasso_node_destroy(providers_node);

  dump = lasso_node_export(server_node);
  lasso_node_destroy(server_node);

  return(dump);
}

gint
lasso_server_add_provider(LassoServer *server,
			  gchar       *metadata,
			  gchar       *public_key,
			  gchar       *ca_certificate)
{
  LassoProvider *provider;

  g_return_val_if_fail(LASSO_IS_SERVER(server), -1);
  g_return_val_if_fail(metadata!=NULL, -2);

  provider = lasso_provider_new(metadata, public_key, ca_certificate);
  g_return_val_if_fail(provider!=NULL, -5);

  /* debug(INFO, "Add a provider(%s)\n", lasso_provider_get_providerID(provider)); */
  g_ptr_array_add(server->providers, provider);

  return(0);
}

void
lasso_server_destroy(LassoServer *server)
{
  g_object_unref(G_OBJECT(server));
}

LassoProvider*
lasso_server_get_provider(LassoServer *server,
			  gchar       *providerID)
{
  LassoProvider *provider;
  xmlChar *id;
  int index, len;
  
  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(providerID!=NULL, NULL);

/*   debug(INFO, "Get information of provider id %s\n", providerID); */

  len = server->providers->len;
  for(index = 0; index<len; index++) {
    provider = g_ptr_array_index(server->providers, index);
    
    id = lasso_provider_get_providerID(provider, NULL);
    if (xmlStrEqual(providerID, id)) {
      xmlFree(id);
      return(provider);
    }
    xmlFree(id);
  }

  return(NULL);
}

gchar *
lasso_server_get_providerID_from_hash(LassoServer *server,
				      gchar       *hash)
{
  LassoProvider *provider;
  gchar *providerID, *hash_providerID;
  int i;

  for(i=0; i<server->providers->len; i++) {
    provider = g_ptr_array_index(server->providers, i);
    providerID = lasso_provider_get_providerID(provider, NULL);
    hash_providerID = lasso_str_hash(providerID, server->private_key);
    if (xmlStrEqual(hash_providerID, hash)) {
      g_free(hash_providerID);
      return(providerID);
    }
    else {
      g_free(providerID);
      g_free(hash_providerID);
    }
  }

  return(NULL);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_server_dispose(LassoServer *server)
{
  guint i;

  if (server->private->dispose_has_run == TRUE) {
    return;
  }
  server->private->dispose_has_run = TRUE;

  debug("Server object 0x%x finalized ...\n", server);

  /* free allocated memory for providers array */
  for (i=0; i<server->providers->len; i++) {
    lasso_provider_destroy(server->providers->pdata[i]);
  }
  g_ptr_array_free(server->providers, TRUE);

  parent_class->dispose(G_OBJECT(server));
}

static void
lasso_server_finalize(LassoServer *server)
{
  debug("Server object 0x%x finalized ...\n", server);

  g_free(server->providerID);
  g_free(server->private_key);
  g_free(server->certificate);

  g_free(server->private);

  parent_class->finalize(G_OBJECT(server));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_server_instance_init(LassoServer *server)
{
  server->private = g_new (LassoServerPrivate, 1);
  server->private->dispose_has_run = FALSE;

  server->providers = g_ptr_array_new();
  server->providerID  = NULL;
  server->private_key = NULL;
  server->certificate = NULL;
  server->signature_method = lassoSignatureMethodRsaSha1;
}

static void
lasso_server_class_init(LassoServerClass *class) {
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_server_dispose;
  gobject_class->finalize = (void *)lasso_server_finalize;
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
  LassoNode   *md_node;
  gchar       *providerID;
  GError      *err = NULL;

  g_return_val_if_fail(metadata != NULL, NULL);

  /* put server metadata in a LassoNode */
  doc = xmlParseFile(metadata);
  root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
  xmlFreeDoc(doc);
  md_node = lasso_node_new();
  LASSO_NODE_GET_CLASS(md_node)->set_xmlNode(md_node, root);
  /* md_node = lasso_node_new_from_xmlNode(root); */
 
  /* get ProviderID in metadata */
  providerID = lasso_node_get_attr_value(md_node, "ProviderID", &err);
  if (providerID == NULL) {
    message(G_LOG_LEVEL_ERROR, err->message);
    g_error_free(err);
    lasso_node_destroy(md_node);
    return (NULL);
  }

  /* Ok, we can create server */
  server = LASSO_SERVER(g_object_new(LASSO_TYPE_SERVER, NULL));

  LASSO_PROVIDER(server)->metadata = md_node;

  server->providerID = providerID;
  server->private_key = g_strdup(private_key);
  server->certificate = g_strdup(certificate);
  server->signature_method = signature_method;

  LASSO_PROVIDER(server)->public_key = g_strdup(public_key);
  LASSO_PROVIDER(server)->ca_certificate = NULL;

  return(server);
}

LassoServer *
lasso_server_new_from_dump(gchar *dump)
{
  LassoNodeClass *server_class, *providers_class;
  LassoNode      *server_node, *providers_node, *provider_node, *entity_node, *server_metadata_node;
  LassoServer    *server;
  LassoProvider  *provider;
  xmlNodePtr      providers_xmlNode, provider_xmlNode;
  xmlChar        *public_key, *ca_certificate, *signature_method;

  server = LASSO_SERVER(g_object_new(LASSO_TYPE_SERVER, NULL));

  server_node  = lasso_node_new_from_dump(dump);
  if(server_node == NULL) {
    message(G_LOG_LEVEL_ERROR, "Error while loading server dump\n");
    return(NULL);
  }
  server_class = LASSO_NODE_GET_CLASS(server_node);

  /* providerID */
  server->providerID = lasso_node_get_attr_value(server_node, LASSO_SERVER_PROVIDERID_NODE, NULL);

  /* private key */
  server->private_key = lasso_node_get_attr_value(server_node, LASSO_SERVER_PRIVATE_KEY_NODE, NULL);

  /* certificate */
  server->certificate = lasso_node_get_attr_value(server_node, LASSO_SERVER_CERTIFICATE_NODE, NULL);

  /* signature method */
  signature_method = lasso_node_get_attr_value(server_node, LASSO_SERVER_SIGNATURE_METHOD_NODE, NULL);
  if (signature_method != NULL) {
    server->signature_method = atoi(signature_method);
    xmlFree(signature_method);
  }

  /* metadata */
  server_metadata_node = lasso_node_get_child(server_node, "EntityDescriptor", NULL);
  LASSO_PROVIDER(server)->metadata = lasso_node_copy(server_metadata_node);
  lasso_node_destroy(server_metadata_node);

  /* public key */
  LASSO_PROVIDER(server)->public_key = lasso_node_get_attr_value(server_node, LASSO_PROVIDER_PUBLIC_KEY_NODE, NULL);

  /* ca_certificate */
  LASSO_PROVIDER(server)->ca_certificate = lasso_node_get_attr_value(server_node, LASSO_PROVIDER_CA_CERTIFICATE_NODE, NULL);

  /* providers */
  providers_node  = lasso_node_get_child(server_node, LASSO_SERVER_PROVIDERS_NODE, NULL);
  if(providers_node != NULL) {
    providers_class = LASSO_NODE_GET_CLASS(providers_node);
    providers_xmlNode = providers_class->get_xmlNode(providers_node);
    provider_xmlNode = providers_xmlNode->children;

    while(provider_xmlNode != NULL){
      if(provider_xmlNode->type==XML_ELEMENT_NODE && xmlStrEqual(provider_xmlNode->name, LASSO_PROVIDER_NODE)){
	/* provider node */
	provider_node = lasso_node_new_from_xmlNode(provider_xmlNode);

	/*  metadata */
	entity_node = lasso_node_get_child(provider_node, "EntityDescriptor", NULL);

	/* public key */
	public_key = lasso_node_get_attr_value(provider_node, LASSO_PROVIDER_PUBLIC_KEY_NODE, NULL);

	/* ca certificate */
	ca_certificate = lasso_node_get_attr_value(provider_node, LASSO_PROVIDER_CA_CERTIFICATE_NODE, NULL);

	/* add provider */
	provider = lasso_provider_new_from_metadata_node(entity_node);
	lasso_node_destroy(entity_node);
	if(public_key != NULL) {
	  lasso_provider_set_public_key(provider, public_key);
	  xmlFree(public_key);
	}
	if(ca_certificate != NULL) {
	  lasso_provider_set_ca_certificate(provider, ca_certificate);
	  xmlFree(ca_certificate);
	}
	lasso_server_add_lasso_provider(server, provider);

	lasso_node_destroy(provider_node);
      }

      provider_xmlNode = provider_xmlNode->next;
    }

    lasso_node_destroy(providers_node);
  }

  lasso_node_destroy(server_node);

  return(server);
}
