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

#include <lasso/protocols/identity.h>

struct _LassoIdentityPrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_identity_destroy(LassoIdentity *identity)
{
  g_object_unref(G_OBJECT(identity));
}

xmlChar *
lasso_identity_dump(LassoIdentity *identity)
{
  LassoNode *identity_node, *nameIdentifier;
  LassoNode *local_nameIdentifier, *remote_nameIdentifier;
  LassoNodeClass *identity_class, *class;
  gchar *dump;

  identity_node = lasso_node_new();
  identity_class = LASSO_NODE_GET_CLASS(identity_node);
  identity_class->set_name(identity_node, LASSO_IDENTITY_NODE);

  /* set the remote providerID */
  identity_class->set_prop(identity_node, LASSO_IDENTITY_REMOTE_PROVIDERID_NODE, identity->remote_providerID);

  /* add the remote name identifier */
  if(identity->remote_nameIdentifier){
    nameIdentifier = lasso_node_new();
    class = LASSO_NODE_GET_CLASS(nameIdentifier);
    class->set_name(nameIdentifier, LASSO_IDENTITY_REMOTE_NAME_IDENTIFIER_NODE);
    remote_nameIdentifier = lasso_node_copy(identity->remote_nameIdentifier);
    class->add_child(nameIdentifier, remote_nameIdentifier, FALSE);
    lasso_node_destroy(remote_nameIdentifier);
    identity_class->add_child(identity_node, nameIdentifier, FALSE);
    lasso_node_destroy(nameIdentifier);
  }

  /* add the local name identifier */
  if(identity->local_nameIdentifier){
    nameIdentifier = lasso_node_new();
    class = LASSO_NODE_GET_CLASS(nameIdentifier);
    class->set_name(nameIdentifier, LASSO_IDENTITY_LOCAL_NAME_IDENTIFIER_NODE);
    local_nameIdentifier = lasso_node_copy(identity->local_nameIdentifier);
    class->add_child(nameIdentifier, local_nameIdentifier, FALSE);
    lasso_node_destroy(local_nameIdentifier);
    identity_class->add_child(identity_node, nameIdentifier, FALSE);
    lasso_node_destroy(nameIdentifier);
  }

  dump = lasso_node_export(identity_node);
  lasso_node_destroy(identity_node);

  return(dump);
}

LassoNode *
lasso_identity_get_local_nameIdentifier(LassoIdentity *identity)
{
  return(LASSO_NODE(identity->local_nameIdentifier));
}

LassoNode *
lasso_identity_get_remote_nameIdentifier(LassoIdentity *identity)
{
  return(LASSO_NODE(identity->remote_nameIdentifier));
}

void
lasso_identity_remove_local_nameIdentifier(LassoIdentity *identity)
{
  if(identity->local_nameIdentifier!=NULL){
    lasso_node_destroy(identity->local_nameIdentifier);
  }
}

void
lasso_identity_remove_remote_nameIdentifier(LassoIdentity *identity)
{
  if(identity->remote_nameIdentifier!=NULL){
    lasso_node_destroy(identity->remote_nameIdentifier);
  }
}

void
lasso_identity_set_local_nameIdentifier(LassoIdentity *identity,
					LassoNode     *nameIdentifier)
{
  identity->local_nameIdentifier = lasso_node_copy(nameIdentifier);
}

void
lasso_identity_set_remote_nameIdentifier(LassoIdentity *identity,
					 LassoNode     *nameIdentifier)
{
  identity->remote_nameIdentifier = lasso_node_copy(nameIdentifier);
}

gboolean
lasso_identity_verify_nameIdentifier(LassoIdentity *identity,
				     LassoNode     *nameIdentifier)
{
  gchar *identity_content, *nameIdentifier_content;

  nameIdentifier_content = lasso_node_get_content(nameIdentifier);
  if(identity->local_nameIdentifier){
    identity_content = lasso_node_get_content(identity->local_nameIdentifier);
    if(xmlStrEqual(identity_content, nameIdentifier_content)){
      return(TRUE);
    }
  }
  if(identity->remote_nameIdentifier){
    identity_content = lasso_node_get_content(identity->remote_nameIdentifier);
    if(xmlStrEqual(identity_content, nameIdentifier_content)){
      return(TRUE);
    }
  }

  return(FALSE);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_identity_dispose(LassoIdentity *identity)
{
  if (identity->private->dispose_has_run) {
    return;
  }
  identity->private->dispose_has_run = TRUE;

  debug(DEBUG, "Identity object 0x%x disposed ...\n", identity);

  /* unref reference counted objects */
  lasso_node_destroy(identity->local_nameIdentifier);
  lasso_node_destroy(identity->remote_nameIdentifier);

  parent_class->dispose(G_OBJECT(identity));
}

static void
lasso_identity_finalize(LassoIdentity *identity)
{
  debug(DEBUG, "Identity object 0x%x finalized ...\n", identity);

  g_free(identity->remote_providerID);

  g_free (identity->private);

  parent_class->finalize(G_OBJECT(identity));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_identity_instance_init(LassoIdentity *identity)
{
  identity->private = g_new (LassoIdentityPrivate, 1);
  identity->private->dispose_has_run = FALSE;

  identity->remote_providerID  = NULL;
  identity->local_nameIdentifier  = NULL;
  identity->remote_nameIdentifier = NULL;
}

static void
lasso_identity_class_init(LassoIdentityClass *g_class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

  parent_class = g_type_class_peek_parent(g_class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_identity_dispose;
  gobject_class->finalize = (void *)lasso_identity_finalize;
}

GType lasso_identity_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoIdentityClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_identity_class_init,
      NULL,
      NULL,
      sizeof(LassoIdentity),
      0,
      (GInstanceInitFunc) lasso_identity_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoIdentity",
				       &this_info, 0);
  }
  return this_type;
}

LassoIdentity*
lasso_identity_new(gchar *remote_providerID)
{
  LassoIdentity *identity;

  g_return_val_if_fail(remote_providerID != NULL, NULL);

  identity = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  identity->remote_providerID = g_strdup(remote_providerID);

  return(identity);
}

LassoIdentity*
lasso_identity_new_from_dump(xmlChar *dump)
{
  LassoIdentity *identity;

  g_return_val_if_fail(dump != NULL, NULL);

  identity = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  return(identity);
}
