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

#include <glib.h>
#include <glib/gprintf.h>

#include <lasso/xml/samlp_response.h>
#include <lasso/protocols/request.h>
#include <lasso/protocols/response.h>
#include <lasso/protocols/authn_response.h>
#include <lasso/environs/profile.h>

struct _LassoProfilePrivate
{
  gboolean dispose_has_run;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public functions                                                          */
/*****************************************************************************/

lassoRequestType
lasso_profile_get_request_type_from_soap_msg(gchar *soap)
{
  LassoNode *soap_node, *body_node, *request_node;
  GPtrArray *children;
  xmlChar *name;
  lassoRequestType type = lassoRequestTypeInvalid;

  soap_node = lasso_node_new_from_dump(soap);
  if (soap_node == NULL) {
    message(G_LOG_LEVEL_WARNING, "Error while build node from soap msg\n");
    return -1;
  }

  body_node = lasso_node_get_child(soap_node, "Body", NULL, NULL);
  if(body_node == NULL) {
    message(G_LOG_LEVEL_WARNING, "Body node not found\n");
    return -2;
  }

  children = lasso_node_get_children(body_node);
  if(children->len > 0) {
    request_node = g_ptr_array_index(children, 0);
    name = lasso_node_get_name(request_node);

    if(xmlStrEqual(name, "Request")) {
      type = lassoRequestTypeLogin;
    }
    else if(xmlStrEqual(name, "LogoutRequest")) {
      type = lassoRequestTypeLogout;
    }
    else if(xmlStrEqual(name, "FederationTerminationNotification")) {
      type = lassoRequestTypeDefederation;
    }
    else if(xmlStrEqual(name, "RegisterNameIdentifierRequest")) {
      type = lassoRequestTypeRegisterNameIdentifier;
    }
    else if(xmlStrEqual(name, "NameIdentifierMappingRequest")) {
      type = lassoRequestTypeNameIdentifierMapping;
    }
    else if(xmlStrEqual(name, "AuthnRequest")) {
      type = lassoRequestTypeLecp;
    }
    else {
      message(G_LOG_LEVEL_WARNING, "Unkown node name : %s\n", name);
    }
    xmlFree(name);
  }

  return type;
}


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar*
lasso_profile_dump(LassoProfile *ctx,
		   const gchar  *name)
{
  LassoNode *node;
  LassoNode *request, *response = NULL;
  gchar *dump = NULL;
  gchar *request_type =  g_new0(gchar, 6);
  gchar *response_type = g_new0(gchar, 6);
  gchar *provider_type = g_new0(gchar, 6);

  node = lasso_node_new();
  if (name != NULL) {
    LASSO_NODE_GET_CLASS(node)->set_name(node, name);
  }
  else {
    LASSO_NODE_GET_CLASS(node)->set_name(node, "LassoProfile");
  }
  LASSO_NODE_GET_CLASS(node)->set_ns(node, lassoLassoHRef, NULL);

  if (ctx->request != NULL) {
    request = lasso_node_copy(ctx->request);
    LASSO_NODE_GET_CLASS(node)->add_child(node, request, FALSE);
    lasso_node_destroy(request);
  }
  if (ctx->response != NULL) {
    response = lasso_node_copy(ctx->response);
    LASSO_NODE_GET_CLASS(node)->add_child(node, response, FALSE);
    lasso_node_destroy(response);
  }

  if (ctx->nameIdentifier != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "NameIdentifier",
					  ctx->nameIdentifier, FALSE);
  }

  if (ctx->remote_providerID != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "RemoteProviderID",
					  ctx->remote_providerID, FALSE);
  }

  if (ctx->msg_url != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "MsgUrl", ctx->msg_url, FALSE);
  }
  if (ctx->msg_body != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "MsgBody", ctx->msg_body, FALSE);
  }
  if (ctx->msg_relayState != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "MsgRelayState",
					  ctx->msg_relayState, FALSE);
  }

  g_sprintf(request_type, "%d", ctx->request_type);
  LASSO_NODE_GET_CLASS(node)->new_child(node, "RequestType", request_type, FALSE);
  g_free(request_type);
  g_sprintf(response_type, "%d", ctx->response_type);
  LASSO_NODE_GET_CLASS(node)->new_child(node, "ResponseType", response_type, FALSE);
  g_free(response_type);
  g_sprintf(provider_type, "%d", ctx->provider_type);
  LASSO_NODE_GET_CLASS(node)->new_child(node, "ProviderType", provider_type, FALSE);
  g_free(provider_type);

  dump = lasso_node_export(node);
  lasso_node_destroy(node);

  return dump;
}

LassoIdentity*
lasso_profile_get_identity(LassoProfile *ctx)
{
  g_return_val_if_fail(LASSO_IS_PROFILE(ctx), NULL);

  if (ctx->identity != NULL) {
    /* return identity copy only if identity isn't empty */
    if (ctx->identity->providerIDs->len > 0) {
      return lasso_identity_copy(ctx->identity);
    }
  }

  return NULL;
}

LassoSession*
lasso_profile_get_session(LassoProfile *ctx)
{
  g_return_val_if_fail(LASSO_IS_PROFILE(ctx), NULL);

  if (ctx->session != NULL) {
    /* return session copy only if session isn't empty */
    if (ctx->session->providerIDs->len > 0) {
      return lasso_session_copy(ctx->session);
    }
  }

  return NULL;
}

gboolean
lasso_profile_is_identity_dirty(LassoProfile *ctx)
{
  if (ctx->identity != NULL) {
    return ctx->identity->is_dirty;
  }
  else {
    return FALSE;
  }
}

gboolean
lasso_profile_is_session_dirty(LassoProfile *ctx)
{
  if (ctx->session != NULL) {
    return ctx->session->is_dirty;
  }
  else {
    return FALSE;
  }
}

gint
lasso_profile_set_remote_providerID(LassoProfile *ctx,
				    gchar        *providerID)
{
  g_free(ctx->remote_providerID);
  ctx->remote_providerID = g_strdup(providerID);
  
  return 1;
}

void
lasso_profile_set_response_status(LassoProfile *ctx,
				  const gchar  *statusCodeValue)
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

gint
lasso_profile_set_identity(LassoProfile  *ctx,
			   LassoIdentity *identity)
{
  g_return_val_if_fail(LASSO_IS_IDENTITY(identity), -1);

  ctx->identity = lasso_identity_copy(identity);
  ctx->identity->is_dirty = FALSE;

  return 0;
}

gint
lasso_profile_set_identity_from_dump(LassoProfile *ctx,
				     const gchar  *dump)
{
  ctx->identity = lasso_identity_new_from_dump((gchar *)dump);
  if (ctx->identity == NULL) {
    message(G_LOG_LEVEL_WARNING, "Failed to create the identity from the identity dump\n");
    return -1;
  }
  ctx->identity->is_dirty = FALSE;

  return 0;
}

gint
lasso_profile_set_session(LassoProfile *ctx,
			  LassoSession *session)
{
  g_return_val_if_fail(LASSO_IS_SESSION(session), -1);

  ctx->session = lasso_session_copy(session);
  ctx->session->is_dirty = FALSE;

  return 0;
}

gint
lasso_profile_set_session_from_dump(LassoProfile *ctx,
				    const gchar  *dump)
{
  ctx->session = lasso_session_new_from_dump((gchar *)dump);
  if (ctx->session == NULL) {
    message(G_LOG_LEVEL_WARNING, "Failed to create the session from the session dump\n");
    return -1;
  }
  ctx->session->is_dirty = FALSE;

  return 0;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_profile_dispose(LassoProfile *ctx)
{
  if (ctx->private->dispose_has_run) {
    return;
  }
  ctx->private->dispose_has_run = TRUE;

  debug("Profile object 0x%x disposed ...\n", ctx);

  /* unref reference counted objects */
  lasso_server_destroy(ctx->server);
  lasso_identity_destroy(ctx->identity);
  lasso_session_destroy(ctx->session);

  lasso_node_destroy(ctx->request);
  lasso_node_destroy(ctx->response);

  parent_class->dispose(G_OBJECT(ctx));
}

static void
lasso_profile_finalize(LassoProfile *ctx)
{
  debug("Profile object 0x%x finalized ...\n", ctx);

  g_free(ctx->nameIdentifier);
  g_free(ctx->remote_providerID);
  g_free(ctx->msg_url);
  g_free(ctx->msg_body);
  g_free(ctx->msg_relayState);

  g_free (ctx->private);

  parent_class->finalize(G_OBJECT(ctx));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

enum {
  LASSO_PROFILE_SERVER = 1,
  LASSO_PROFILE_IDENTITY,
  LASSO_PROFILE_SESSION,
  LASSO_PROFILE_PROVIDER_TYPE
};

static void
lasso_profile_instance_init(GTypeInstance *instance,
			    gpointer       g_class)
{
  LassoProfile *ctx = LASSO_PROFILE(instance);

  ctx->private = g_new (LassoProfilePrivate, 1);
  ctx->private->dispose_has_run = FALSE;

  ctx->server = NULL;
  ctx->identity = NULL;
  ctx->session  = NULL;
  ctx->request  = NULL;
  ctx->response = NULL;
  ctx->nameIdentifier = NULL;
  ctx->request_type  = lassoMessageTypeNone;
  ctx->response_type = lassoMessageTypeNone;
  ctx->provider_type = lassoProviderTypeNone;
  
  ctx->remote_providerID = NULL;
  
  ctx->msg_url        = NULL;
  ctx->msg_body       = NULL;
  ctx->msg_relayState = NULL;
}

static void
lasso_profile_set_property (GObject      *object,
			    guint         property_id,
			    const GValue *value,
			    GParamSpec   *pspec)
{
  LassoProfile *self = LASSO_PROFILE(object);

  switch (property_id) {
  case LASSO_PROFILE_SERVER: {
    if (self->server) {
      g_object_unref(self->server);
    }
    self->server = g_value_get_pointer (value);
  }
    break;
  case LASSO_PROFILE_IDENTITY: {
    if (self->identity) {
      g_object_unref(self->identity);
    }
    self->identity = g_value_get_pointer (value);
  }
    break;
  case LASSO_PROFILE_SESSION: {
    if (self->session) {
      g_object_unref(self->session);
    }
    self->session = g_value_get_pointer (value);
  }
    break;
  case LASSO_PROFILE_PROVIDER_TYPE: {
    self->provider_type = g_value_get_uint (value);
  }
    break;
  default:
    /* We don't have any other property... */
    g_assert (FALSE);
    break;
  }
}

static void
lasso_profile_get_property(GObject    *object,
			   guint       property_id,
			   GValue     *value,
			   GParamSpec *pspec)
{
}

static void
lasso_profile_class_init(gpointer g_class,
			 gpointer g_class_data)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);
  GParamSpec *pspec;

  parent_class = g_type_class_peek_parent(g_class);
  /* override parent class methods */
  gobject_class->set_property = lasso_profile_set_property;
  gobject_class->get_property = lasso_profile_get_property;

  pspec = g_param_spec_pointer ("server",
				"server metadata and keys/certs",
				"Data of server",
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_SERVER,
                                   pspec);

  pspec = g_param_spec_pointer ("identity",
				"user's federations",
				"User's federations",
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_IDENTITY,
                                   pspec);

  pspec = g_param_spec_pointer ("session",
				"user's assertions",
				"User's assertions",
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_SESSION,
                                   pspec);

  pspec = g_param_spec_uint ("provider_type",
			     "provider type",
			     "The provider type",
			     0,
			     G_MAXINT,
			     0,
			     G_PARAM_READABLE | G_PARAM_WRITABLE);
  g_object_class_install_property (gobject_class,
                                   LASSO_PROFILE_PROVIDER_TYPE,
                                   pspec);

  gobject_class->dispose  = (void *)lasso_profile_dispose;
  gobject_class->finalize = (void *)lasso_profile_finalize;
}

GType lasso_profile_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoProfileClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_profile_class_init,
      NULL,
      NULL,
      sizeof(LassoProfile),
      0,
      (GInstanceInitFunc) lasso_profile_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoProfile",
				       &this_info, 0);
  }
  return this_type;
}

LassoProfile*
lasso_profile_new(LassoServer   *server,
		  LassoIdentity *identity,
		  LassoSession  *session)
{
  LassoProfile *ctx;

  g_return_val_if_fail(server != NULL, NULL);

  ctx = LASSO_PROFILE(g_object_new(LASSO_TYPE_PROFILE,
				   "server", lasso_server_copy(server),
				   "identity", lasso_identity_copy(identity),
				   "session", lasso_session_copy(session),
				   NULL));

  return ctx;
}
