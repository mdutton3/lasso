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

#include <lasso/protocols/federation.h>

struct _LassoFederationPrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoFederation*
lasso_federation_copy(LassoFederation *federation)
{
  LassoFederation *copy;

  g_return_val_if_fail(LASSO_IS_FEDERATION(federation), NULL);

  copy = LASSO_FEDERATION(g_object_new(LASSO_TYPE_FEDERATION, NULL));
  copy->remote_providerID = g_strdup(federation->remote_providerID);
  if (federation->local_nameIdentifier != NULL) {
    copy->local_nameIdentifier = lasso_node_copy(federation->local_nameIdentifier);
  }
  if (federation->remote_nameIdentifier != NULL) {
    copy->remote_nameIdentifier = lasso_node_copy(federation->remote_nameIdentifier);
  }

  return(copy);
}

void
lasso_federation_destroy(LassoFederation *federation)
{
  g_object_unref(G_OBJECT(federation));
}

xmlChar *
lasso_federation_dump(LassoFederation *federation)
{
  LassoNode *federation_node, *nameIdentifier;
  LassoNode *local_nameIdentifier, *remote_nameIdentifier;
  LassoNodeClass *federation_class, *class;
  gchar *dump;

  federation_node = lasso_node_new();
  federation_class = LASSO_NODE_GET_CLASS(federation_node);
  federation_class->set_name(federation_node, LASSO_FEDERATION_NODE);

  /* set the remote providerID */
  federation_class->set_prop(federation_node, LASSO_FEDERATION_REMOTE_PROVIDERID_NODE,
			     federation->remote_providerID);

  /* add the remote name identifier */
  if(federation->remote_nameIdentifier) {
    nameIdentifier = lasso_node_new();
    class = LASSO_NODE_GET_CLASS(nameIdentifier);
    class->set_name(nameIdentifier, LASSO_FEDERATION_REMOTE_NAME_IDENTIFIER_NODE);
    remote_nameIdentifier = lasso_node_copy(federation->remote_nameIdentifier);
    class->add_child(nameIdentifier, remote_nameIdentifier, FALSE);
    lasso_node_destroy(remote_nameIdentifier);
    federation_class->add_child(federation_node, nameIdentifier, FALSE);
    lasso_node_destroy(nameIdentifier);
  }

  /* add the local name identifier */
  if(federation->local_nameIdentifier) {
    nameIdentifier = lasso_node_new();
    class = LASSO_NODE_GET_CLASS(nameIdentifier);
    class->set_name(nameIdentifier, LASSO_FEDERATION_LOCAL_NAME_IDENTIFIER_NODE);
    local_nameIdentifier = lasso_node_copy(federation->local_nameIdentifier);
    class->add_child(nameIdentifier, local_nameIdentifier, FALSE);
    lasso_node_destroy(local_nameIdentifier);
    federation_class->add_child(federation_node, nameIdentifier, FALSE);
    lasso_node_destroy(nameIdentifier);
  }

  dump = lasso_node_export(federation_node);
  lasso_node_destroy(federation_node);

  return(dump);
}

LassoNode *
lasso_federation_get_local_nameIdentifier(LassoFederation *federation)
{
  return(lasso_node_copy(federation->local_nameIdentifier));
}

LassoNode *
lasso_federation_get_remote_nameIdentifier(LassoFederation *federation)
{
  return(lasso_node_copy(federation->remote_nameIdentifier));
}

void
lasso_federation_remove_local_nameIdentifier(LassoFederation *federation)
{
  if(federation->local_nameIdentifier != NULL) {
    lasso_node_destroy(federation->local_nameIdentifier);
  }
}

void
lasso_federation_remove_remote_nameIdentifier(LassoFederation *federation)
{
  if(federation->remote_nameIdentifier != NULL){
    lasso_node_destroy(federation->remote_nameIdentifier);
  }
}

void
lasso_federation_set_local_nameIdentifier(LassoFederation *federation,
					  LassoNode       *nameIdentifier)
{
  federation->local_nameIdentifier = lasso_node_copy(nameIdentifier);
}

void
lasso_federation_set_remote_nameIdentifier(LassoFederation *federation,
					   LassoNode       *nameIdentifier)
{
  federation->remote_nameIdentifier = lasso_node_copy(nameIdentifier);
}

gboolean
lasso_federation_verify_nameIdentifier(LassoFederation *federation,
				       LassoNode       *nameIdentifier)
{
  gchar *federation_content, *nameIdentifier_content;

  nameIdentifier_content = lasso_node_get_content(nameIdentifier);
  if(federation->local_nameIdentifier != NULL) {
    federation_content = lasso_node_get_content(federation->local_nameIdentifier);
    if(xmlStrEqual(federation_content, nameIdentifier_content)) {
      xmlFree(federation_content);
      return(TRUE);
    }
    xmlFree(federation_content);
  }
  if(federation->remote_nameIdentifier != NULL) {
    federation_content = lasso_node_get_content(federation->remote_nameIdentifier);
    if(xmlStrEqual(federation_content, nameIdentifier_content)) {
      xmlFree(federation_content);
      return(TRUE);
    }
    xmlFree(federation_content);
  }
  xmlFree(nameIdentifier_content);
    
  return(FALSE);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_federation_dispose(LassoFederation *federation)
{
  if (federation->private->dispose_has_run) {
    return;
  }
  federation->private->dispose_has_run = TRUE;

  debug("Federation object 0x%x disposed ...\n", federation);

  /* unref reference counted objects */
  lasso_node_destroy(federation->local_nameIdentifier);
  lasso_node_destroy(federation->remote_nameIdentifier);

  parent_class->dispose(G_OBJECT(federation));
}

static void
lasso_federation_finalize(LassoFederation *federation)
{
  debug("Federation object 0x%x finalized ...\n", federation);

  g_free(federation->remote_providerID);
  g_free(federation->private);

  parent_class->finalize(G_OBJECT(federation));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_federation_instance_init(LassoFederation *federation)
{
  federation->private = g_new (LassoFederationPrivate, 1);
  federation->private->dispose_has_run = FALSE;

  federation->remote_providerID  = NULL;
  federation->local_nameIdentifier  = NULL;
  federation->remote_nameIdentifier = NULL;
}

static void
lasso_federation_class_init(LassoFederationClass *g_class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

  parent_class = g_type_class_peek_parent(g_class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_federation_dispose;
  gobject_class->finalize = (void *)lasso_federation_finalize;
}

GType lasso_federation_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoFederationClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_federation_class_init,
      NULL,
      NULL,
      sizeof(LassoFederation),
      0,
      (GInstanceInitFunc) lasso_federation_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoFederation",
				       &this_info, 0);
  }
  return this_type;
}

LassoFederation*
lasso_federation_new(gchar *remote_providerID)
{
  LassoFederation *federation;

  g_return_val_if_fail(remote_providerID != NULL, NULL);

  federation = LASSO_FEDERATION(g_object_new(LASSO_TYPE_FEDERATION, NULL));

  federation->remote_providerID = g_strdup(remote_providerID);

  return(federation);
}

LassoFederation*
lasso_federation_new_from_dump(xmlChar *dump)
{
  LassoFederation *federation;

  g_return_val_if_fail(dump != NULL, NULL);

  federation = LASSO_FEDERATION(g_object_new(LASSO_TYPE_FEDERATION, NULL));

  return(federation);
}
