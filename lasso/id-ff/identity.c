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

#include <lasso/environs/identity.h>

#define LASSO_IDENTITY_NODE                   "LassoIdentity"
#define LASSO_IDENTITY_FEDERATIONS_NODE       "LassoFederations"
#define LASSO_IDENTITY_FEDERATION_NODE        "LassoFederation"
#define LASSO_IDENTITY_REMOTE_PROVIDERID_ATTR "RemoteProviderID"

struct _LassoIdentityPrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* private functions                                                         */
/*****************************************************************************/

static void
lasso_identity_copy_federation(gpointer key,
			       gpointer value,
			       gpointer federations)
{
  g_hash_table_insert((GHashTable *)federations, g_strdup((gchar *)key),
		      lasso_federation_copy(LASSO_FEDERATION(value)));
}

static void
lasso_identity_dump_federation(gpointer   key,
			       gpointer   value,
			       LassoNode *federations)
{
  LassoNode      *federation_node;
  LassoNodeClass *federation_class;
  xmlChar        *dump;

  dump = lasso_federation_dump(LASSO_FEDERATION(value));
  federation_node = lasso_node_new_from_dump(dump);
  xmlFree(dump);
  federation_class = LASSO_NODE_GET_CLASS(federation_node);
  federation_class->add_child(federations, federation_node, TRUE);
  lasso_node_destroy(federation_node);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_identity_add_federation(LassoIdentity   *identity,
			      gchar           *remote_providerID,
			      LassoFederation *federation)
{
  LassoFederation *old_federation;
  gboolean found = FALSE;
  int i;

  g_return_val_if_fail(identity != NULL, -1);
  g_return_val_if_fail(remote_providerID != NULL, -2);
  g_return_val_if_fail(federation != NULL, -3);

  /* add the remote provider id if not already saved */
  for(i = 0; i<identity->providerIDs->len; i++) {
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(identity->providerIDs, i))) {
      found = TRUE;
      break;
    }
  }
  if(found == TRUE) {
    debug("A federation existed already for this providerID, it was replaced by the new one.\n");
  }
  else {
    g_ptr_array_add(identity->providerIDs, g_strdup(remote_providerID));
  }

  /* add the federation, replace if one already exists */
  g_hash_table_insert(identity->federations, g_strdup(remote_providerID), federation);

  identity->is_dirty = TRUE;

  return(0);
}

LassoIdentity*
lasso_identity_copy(LassoIdentity *identity)
{
  LassoIdentity *copy;
  guint i;

  if (identity == NULL) {
    return(NULL);
  }

  copy = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  copy->providerIDs = g_ptr_array_new();
  for(i=0; i<identity->providerIDs->len; i++) {
    g_ptr_array_add(copy->providerIDs,
		    g_strdup(g_ptr_array_index(identity->providerIDs, i)));
  }
  copy->federations = g_hash_table_new_full(g_str_hash, g_str_equal,
					    (GDestroyNotify)g_free,
					    (GDestroyNotify)lasso_node_destroy);
  g_hash_table_foreach(identity->federations, (GHFunc)lasso_identity_copy_federation,
		       (gpointer)copy->federations);
  copy->is_dirty = identity->is_dirty;

  return(copy);
}

void
lasso_identity_destroy(LassoIdentity *identity)
{
  if (LASSO_IS_IDENTITY(identity)) {
    g_object_unref(G_OBJECT(identity));
  }
}

gchar*
lasso_identity_dump(LassoIdentity *identity)
{
  LassoNode *identity_node, *federations_node;
  int table_size;
  xmlChar *dump;

  g_return_val_if_fail(identity != NULL, NULL);

  identity_node = lasso_node_new();
  LASSO_NODE_GET_CLASS(identity_node)->set_name(identity_node, LASSO_IDENTITY_NODE);

  /* dump the federations */
  table_size = g_hash_table_size(identity->federations);
  if (table_size > 0) {
    federations_node = lasso_node_new();
    LASSO_NODE_GET_CLASS(federations_node)->set_name(federations_node,
						     LASSO_IDENTITY_FEDERATIONS_NODE);
    g_hash_table_foreach(identity->federations, (GHFunc)lasso_identity_dump_federation,
			 federations_node);
    LASSO_NODE_GET_CLASS(identity_node)->add_child(identity_node, federations_node, FALSE);
    lasso_node_destroy(federations_node);
  }

  dump = lasso_node_export(identity_node);

  lasso_node_destroy(identity_node);

  return(dump);
}

LassoFederation*
lasso_identity_get_federation(LassoIdentity *identity,
			      gchar         *remote_providerID)
{
  g_return_val_if_fail(identity != NULL, NULL);
  g_return_val_if_fail(remote_providerID != NULL, NULL);

  LassoFederation *federation;

  federation = (LassoFederation *)g_hash_table_lookup(identity->federations,
						      remote_providerID);
  if (federation == NULL) {
    debug("No Federation found with remote ProviderID = %s\n", remote_providerID);
  }

  /* FIXME: federation should be a copy (fix lasso_identity_add_federation too) */
  return(federation);
}

gchar*
lasso_identity_get_next_federation_remote_providerID(LassoIdentity *identity)
{
  gchar *remote_providerID;

  g_return_val_if_fail(identity!=NULL, NULL);

  if(identity->providerIDs->len == 0) {
    return(NULL);
  }

  remote_providerID = g_strdup(g_ptr_array_index(identity->providerIDs, 0));

  return(remote_providerID);
}

gint
lasso_identity_remove_federation(LassoIdentity *identity,
				 gchar         *remote_providerID)
{
  LassoFederation *federation;
  int i;

  g_return_val_if_fail(identity != NULL, -1);
  g_return_val_if_fail(remote_providerID != NULL, -2);

  /* remove the federation */
  federation = lasso_identity_get_federation(identity, remote_providerID);
  if (federation != NULL) {
    g_hash_table_remove(identity->federations, remote_providerID);
  }
  else {
    debug("Failed to remove federation for remote Provider %s\n", remote_providerID);
  }

  /* remove the federation remote provider id */
  for(i = 0; i<identity->providerIDs->len; i++) {
    if(xmlStrEqual(remote_providerID, g_ptr_array_index(identity->providerIDs, i))) {
      debug("Remove federation of %s\n", remote_providerID);
      g_ptr_array_remove_index(identity->providerIDs, i);
      break;
    }
  }

  identity->is_dirty = TRUE;

  return(0);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_identity_dispose(LassoIdentity *identity)
{
  if (identity->private->dispose_has_run == TRUE) {
    return;
  }
  identity->private->dispose_has_run = TRUE;

  debug("Identity object 0x%x disposed ...\n", identity);

  g_hash_table_destroy(identity->federations);
  identity->federations = NULL;

  parent_class->dispose(G_OBJECT(identity));
}

static void
lasso_identity_finalize(LassoIdentity *identity)
{
  gint i;

  debug("Identity object 0x%x finalized ...\n", identity);

  /* free allocated memory for providerIDs array */
  for (i=0; i<identity->providerIDs->len; i++) {
    g_free(identity->providerIDs->pdata[i]);
    identity->providerIDs->pdata[i] = NULL;
  }
  g_ptr_array_free(identity->providerIDs, TRUE);
  identity->providerIDs = NULL;

  g_free(identity->private);
  identity->private = NULL;

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

  identity->providerIDs = g_ptr_array_new();
  identity->federations = g_hash_table_new_full(g_str_hash, g_str_equal,
						(GDestroyNotify)g_free,
						(GDestroyNotify)lasso_federation_destroy);
  identity->is_dirty = TRUE;
}

static void
lasso_identity_class_init(LassoIdentityClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
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
lasso_identity_new()
{
  LassoIdentity *identity;

  identity = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  return(identity);
}

LassoIdentity*
lasso_identity_new_from_dump(gchar *dump)
{
  LassoNode *identity_node;
  LassoNode *federations_node, *federation_node;
  LassoNode *nis, *ni, *nameIdentifier;

  LassoNodeClass *federations_class;

  xmlNodePtr federations_xmlNode, federation_xmlNode;

  LassoIdentity *identity;

  LassoFederation  *federation;

  xmlChar *str, *remote_providerID;

  GError *err = NULL;

  g_return_val_if_fail(dump != NULL, NULL);

  /* new object */
  identity = LASSO_IDENTITY(g_object_new(LASSO_TYPE_IDENTITY, NULL));

  /* get identity */
  identity_node = lasso_node_new_from_dump(dump);
  if (identity_node == NULL) {
    message(G_LOG_LEVEL_WARNING, "Can't create a identity from dump\n");
    return (NULL);
  }

  /* federations */
  federations_node = lasso_node_get_child(identity_node,
					  LASSO_IDENTITY_FEDERATIONS_NODE,
					  NULL, NULL);
  if (federations_node != NULL) {
    federations_class = LASSO_NODE_GET_CLASS(federations_node);
    federations_xmlNode = federations_class->get_xmlNode(federations_node);
    federation_xmlNode = federations_xmlNode->children;

    while (federation_xmlNode != NULL) {
      if (federation_xmlNode->type==XML_ELEMENT_NODE && \
	  xmlStrEqual(federation_xmlNode->name, LASSO_IDENTITY_FEDERATION_NODE)) {
	federation_node = lasso_node_new_from_xmlNode(federation_xmlNode);
	remote_providerID = lasso_node_get_attr_value(federation_node,
						      LASSO_FEDERATION_REMOTE_PROVIDERID_NODE, &err);
	if(remote_providerID==NULL){
	  message(G_LOG_LEVEL_WARNING, err->message);
	  g_error_free(err);
	  lasso_node_destroy(federation_node);
	  federation_xmlNode = federation_xmlNode->next;
	  continue;
	}

	/* new federation */
	federation = lasso_federation_new(remote_providerID);

	/* local name identifier */
	nis = lasso_node_get_child(federation_node,
				   LASSO_FEDERATION_LOCAL_NAME_IDENTIFIER_NODE,
				   NULL, NULL);
	if (nis != NULL) {
	  ni = lasso_node_get_child(nis, "NameIdentifier", NULL, NULL);
	  if (ni != NULL) {
	    /* content */
	    str = lasso_node_get_content(ni, NULL);
	    nameIdentifier = lasso_saml_name_identifier_new(str);
	    xmlFree(str);
	    /* NameQualifier */
	    str = lasso_node_get_attr_value(ni, "NameQualifier", NULL);
	    if (str != NULL) {
	      lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier), str);
	      xmlFree(str);
	    }
	    /* format */
	    str = lasso_node_get_attr_value(ni, "Format", NULL);
	    if (str != NULL) {
	      lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier), str);
	      xmlFree(str);
	    }
	    lasso_federation_set_local_nameIdentifier(federation, nameIdentifier);
	    debug("  ... add local name identifier %s\n", lasso_node_get_content(ni, NULL));
	    lasso_node_destroy(ni);
	    lasso_node_destroy(nameIdentifier);
	  }
	  lasso_node_destroy(nis);
	}

	/* remote name identifier */
	nis = lasso_node_get_child(federation_node,
				   LASSO_FEDERATION_REMOTE_NAME_IDENTIFIER_NODE,
				   NULL, NULL);
	if (nis != NULL) {
	  ni = lasso_node_get_child(nis, "NameIdentifier", NULL, NULL);
	  if (ni != NULL) {
	    /* content */
	    str = lasso_node_get_content(ni, NULL);
	    nameIdentifier = lasso_saml_name_identifier_new(str);
	    xmlFree(str);
	    /* NameQualifier */
	    str = lasso_node_get_attr_value(ni, "NameQualifier", NULL);
	    if (str != NULL) {
	      lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier), str);
	      xmlFree(str);
	    }
	    /* format */
	    str = lasso_node_get_attr_value(ni, "Format", NULL);
	    if (str != NULL) {
	      lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier), str);
	      xmlFree(str);
	    }
	    lasso_federation_set_remote_nameIdentifier(federation, nameIdentifier);
	    debug("  ... add local name identifier %s\n", lasso_node_get_content(ni, NULL));
	    lasso_node_destroy(ni);
	    lasso_node_destroy(nameIdentifier);
	  }
	  lasso_node_destroy(nis);
	}

	debug("Add federation for %s\n", remote_providerID);
	lasso_identity_add_federation(identity, remote_providerID, federation);

	xmlFree(remote_providerID);
	lasso_node_destroy(federation_node);
      }

      federation_xmlNode = federation_xmlNode->next;
    }

    lasso_node_destroy(federations_node);
  }

  lasso_node_destroy(identity_node);

  return (identity);
}
