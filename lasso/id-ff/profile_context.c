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

#include <lasso/xml/samlp_response.h>
#include <lasso/protocols/request.h>
#include <lasso/protocols/response.h>
#include <lasso/protocols/authn_response.h>
#include <lasso/environs/profile_context.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_profile_context_set_local_providerID(LassoProfileContext *ctx,
					   gchar               *providerID)
{
  if (ctx->local_providerID) {
    free(ctx->local_providerID);
  }
  ctx->local_providerID = (char *)malloc(strlen(providerID)+1);
  strcpy(ctx->local_providerID, providerID);
  
  return (1);
}

gint
lasso_profile_context_set_remote_providerID(LassoProfileContext *ctx,
					    gchar               *providerID)
{
  if (ctx->remote_providerID) {
    free(ctx->remote_providerID);
  }
  ctx->remote_providerID = (char *)malloc(strlen(providerID)+1);
  strcpy(ctx->remote_providerID, providerID);
  
  return (1);
}

void
lasso_profile_context_set_response_status(LassoProfileContext *ctx,
					  const xmlChar       *statusCodeValue)
{
  LassoNode *status, *status_code;

  status = lasso_samlp_status_new();

  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    statusCodeValue);

  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));

  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(ctx->response),
				  LASSO_SAMLP_STATUS(status));
  lasso_node_destroy(status_code);
  lasso_node_destroy(status);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

enum {
  LASSO_PROFILE_CONTEXT_SERVER = 1,
  LASSO_PROFILE_CONTEXT_USER,
  LASSO_PROFILE_CONTEXT_LOCAL_PROVIDERID,
  LASSO_PROFILE_CONTEXT_REMOTE_PROVIDERID,
};

static void
lasso_profile_context_instance_init(GTypeInstance   *instance,
				    gpointer         g_class)
{
  LassoProfileContext *ctx = LASSO_PROFILE_CONTEXT(instance);

  ctx->server = NULL;
  ctx->user   = NULL;
  ctx->request  = NULL;
  ctx->response = NULL;
  ctx->local_providerID  = NULL;
  ctx->remote_providerID = NULL;
}

static void
lasso_profile_context_set_property (GObject      *object,
				    guint         property_id,
				    const GValue *value,
				    GParamSpec   *pspec)
{
  LassoProfileContext *self = LASSO_PROFILE_CONTEXT(object);

  switch (property_id) {
  case LASSO_PROFILE_CONTEXT_SERVER: {
    if (self->server) {
      g_object_unref(self->server);
    }
    self->server = g_value_get_pointer (value);
  }
    break;
  case LASSO_PROFILE_CONTEXT_USER: {
    if (self->user) {
      g_object_unref(self->user);
    }
    self->user = g_value_get_pointer (value);
  }
    break;
  case LASSO_PROFILE_CONTEXT_LOCAL_PROVIDERID: {
    g_free (self->local_providerID);
    self->local_providerID = g_value_dup_string (value);
  }
    break;
  case LASSO_PROFILE_CONTEXT_REMOTE_PROVIDERID: {
    g_free (self->remote_providerID);
    self->remote_providerID = g_value_dup_string (value);
  }
    break;
  default:
    /* We don't have any other property... */
    g_assert (FALSE);
    break;
  }
}

static void
lasso_profile_context_get_property (GObject      *object,
				    guint         property_id,
				    GValue       *value,
				    GParamSpec   *pspec)
{
}

static void
lasso_profile_context_class_init(gpointer g_class,
				 gpointer g_class_data)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);
  GParamSpec *pspec;

  gobject_class->set_property = lasso_profile_context_set_property;
  gobject_class->get_property = lasso_profile_context_get_property;

  pspec = g_param_spec_pointer ("server",
				"server metadata and keys/certs",
				"Set datas of server",
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_CONTEXT_SERVER,
                                   pspec);

  pspec = g_param_spec_pointer ("user",
				"user assertion and identities",
				"Set user's datas",
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_CONTEXT_USER,
                                   pspec);

  pspec = g_param_spec_string ("local_providerID",
			       "local ProviderID",
			       "Set local ProviderID",
			       NULL,
			       G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_CONTEXT_LOCAL_PROVIDERID,
                                   pspec);

  pspec = g_param_spec_string ("remote_providerID",
			       "remote ProviderID",
			       "Set remote ProviderID",
			       NULL,
			       G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_CONTEXT_REMOTE_PROVIDERID,
                                   pspec);
}

GType lasso_profile_context_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoProfileContextClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_profile_context_class_init,
      NULL,
      NULL,
      sizeof(LassoProfileContext),
      0,
      (GInstanceInitFunc) lasso_profile_context_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoProfileContext",
				       &this_info, 0);
  }
  return this_type;
}

LassoProfileContext*
lasso_profile_context_new(LassoServer *server,
			  LassoUser   *user,
			  gchar       *local_providerID,
			  gchar       *remote_providerID)
{
  g_return_val_if_fail(server != NULL, NULL);
  g_return_val_if_fail(local_providerID != NULL, NULL);
  g_return_val_if_fail(remote_providerID != NULL, NULL);

  LassoProfileContext *ctx;

  ctx = LASSO_PROFILE_CONTEXT(g_object_new(LASSO_TYPE_PROFILE_CONTEXT,
					   "server", server,
					   "user", user,
					   "local_providerID", local_providerID,
					   "remote_providerID", remote_providerID,
					   NULL));

  return (ctx);
}
