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
#include <lasso/environs/context.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

static void
set_response_status(LassoNode     *response,
		    const xmlChar *statusCodeValue)
{
  LassoNode *status, *status_code;

  status = lasso_samlp_status_new();

  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    statusCodeValue);

  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));

  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				  LASSO_SAMLP_STATUS(status));
  lasso_node_destroy(status_code);
  lasso_node_destroy(status);
}

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
lasso_profile_context_set_peer_providerID(LassoProfileContext *ctx,
					  gchar               *providerID)
{
  if (ctx->peer_providerID) {
    free(ctx->peer_providerID);
  }
  ctx->peer_providerID = (char *)malloc(strlen(providerID)+1);
  strcpy(ctx->peer_providerID, providerID);
  
  return (1);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

enum {
  LASSO_PROFILE_CONTEXT_SERVER = 1,
  LASSO_PROFILE_CONTEXT_USER   = 2,
};

static void
lasso_profile_context_instance_init(GTypeInstance   *instance,
				    gpointer         g_class)
{
  LassoProfileContext *ctx = LASSO_PROFILE_CONTEXT(instance);

  ctx->user = NULL;
  ctx->request  = NULL;
  ctx->response = NULL;
  ctx->local_providerID = NULL;
  ctx->peer_providerID = NULL;
  ctx->request_protocol_method = 0;
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
    g_object_unref(self->server);
    self->server = g_value_get_pointer (value);
  }
    break;
  case LASSO_PROFILE_CONTEXT_USER: {
    g_object_unref(self->user);
    self->user = g_value_get_pointer (user);
  }
    break;
  default:
    /* We don't have any other property... */
    g_assert (FALSE);
    break;
  }
}

static void
lasso_profile_context_class_init(gpointer g_class,
				 gpointer g_class_data)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);
  LassoProfileContextClass *klass = LASSO_PROFILE_CONTEXT_CLASS (g_class);
  GParamSpec *pspec;

  gobject_class->set_property = lasso_profile_context_set_property;

  pspec = g_param_spec_pointer ("server",
				"servers metadata and keys/cert",
				"Set datas of server",
				NULL /* default value */,
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_CONTEXT_SERVER,
                                   pspec);

  pspec = g_param_spec_pointer ("user",
				"user assertion and identities",
				"Set user's datas",
				NULL /* default value */,
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_CONTEXT_USER,
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
lasso_profile_context_new(LassoServerProfileContext *server,
			  LassoUserProfileContext   *user,
			  gchar              *local_providerID,
			  gchar              *peer_providerID)
{
  /* load the ProviderID name or a reference to the provider ? */
  g_return_val_if_fail(local_providerID != NULL, NULL);
  g_return_val_if_fail(peer_providerID != NULL, NULL);

  LassoProfileContext *ctx;

  ctx = g_object_new(LASSO_TYPE_PROFILE_CONTEXT, NULL);

  ctx->server = server;

  if (user != NULL) {
    ctx->user = user;
  }

  lasso_profile_context_set_local_providerID(ctx, local_providerID);
  lasso_profile_context_set_peer_providerID(ctx, peer_providerID);

  return (ctx);
}
