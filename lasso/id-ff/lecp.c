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

#include <lasso/environs/lecp.h>

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_lecp_build_authn_request_msg(LassoLecp *lecp)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  lecp->msg_body = lasso_node_export_to_soap(lecp->authnRequest);
  if(lecp->msg_body==NULL){
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnRequest to soap msg\n");
    return(-2);
  }

  return(0);
}

gint
lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  /* FIXME : export to base 64 or simple xml dump */
  lecp->msg_body = lasso_node_export_to_base64(lecp->request);
  if(lecp->msg_body==NULL){
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnRequestEnvelope to msg\n");
    return(-2);
  }

  return(0);
}

gint
lasso_lecp_build_authn_response_msg(LassoLecp *lecp)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  lecp->msg_body = lasso_node_export_to_base64(lecp->authnResponse);
  if(lecp->msg_body==NULL){
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnResponse to soap msg\n");
    return(-2);
  }

  return(0);
}

gint
lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  lecp->msg_body = lasso_node_export_to_soap(lecp->response);
  if (lecp->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnResponseEnvelope to msg\n");
    return(-2);
  }

  return(0);
}

void
lasso_lecp_destroy(LassoLecp *lecp)
{
  g_object_unref(G_OBJECT(lecp));
}


gint
lasso_lecp_init_authn_request_envelope(LassoLecp         *lecp,
				       LassoAuthnRequest *authnRequest)
{
  gchar *assertionConsumerServiceURL;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(LASSO_IS_AUTHN_REQUEST(authnRequest), -1);

  assertionConsumerServiceURL = lasso_provider_get_assertionConsumerServiceURL(LASSO_PROVIDER(lecp->server),
									       lassoProviderTypeSp,
									       NULL);

  if(assertionConsumerServiceURL==NULL){
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found\n");
    return(-1);
  }

  lecp->request = lasso_authn_request_envelope_new(authnRequest,
						   lecp->server->providerID,
						   assertionConsumerServiceURL);
  if(lecp->request==NULL){
    message(G_LOG_LEVEL_CRITICAL, "Error while building request\n");
    return(-1);
  }

  g_free(assertionConsumerServiceURL);

  return(0);
}

gint
lasso_lecp_init_authn_response_envelope(LassoLecp          *lecp,
					LassoAuthnRequest  *authnRequest,
					LassoAuthnResponse *authnResponse)
{
  LassoProvider *provider;
  gchar *providerID, *assertionConsumerServiceURL;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(LASSO_IS_AUTHN_REQUEST(authnRequest), -1);

  providerID = lasso_node_get_child_content(LASSO_NODE(authnRequest), "ProviderID",
					    NULL, NULL);
  if(providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "ProviderID not found\n");
    return(-1);
  }

  provider = lasso_server_get_provider(lecp->server, providerID);
  assertionConsumerServiceURL = lasso_provider_get_assertionConsumerServiceURL(provider,
									       lassoProviderTypeSp,
									       NULL);
  if(providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found\n");
    return(-1);
  }

  lecp->response = lasso_authn_response_envelope_new(authnResponse,
						     assertionConsumerServiceURL);

  g_free(assertionConsumerServiceURL);

  return(0);
}

gint
lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp,
					      gchar     *request_msg)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(request_msg!=NULL, -2);

  lecp->request = lasso_authn_request_envelope_new_from_export(request_msg, lassoNodeExportTypeBase64);
  if (lecp->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the authentication request envelope\n");
    return(-3);
  }

  lecp->authnRequest = lasso_authn_request_envelope_get_authnRequest(LASSO_AUTHN_REQUEST_ENVELOPE(lecp->request));
  if (lecp->authnRequest == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found\n");
    return(-4);
  }

  return(0);
}

gint
lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp,
					       gchar     *response_msg)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(response_msg!=NULL, -2);

  lecp->response = lasso_authn_response_envelope_new_from_export(response_msg, lassoNodeExportTypeSoap);
  if (lecp->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the authentication response envelope\n");
    return(-3);
  }

  lecp->authnResponse = lasso_authn_response_envelope_get_authnResponse(LASSO_AUTHN_RESPONSE_ENVELOPE(lecp->response));
  if (lecp->authnResponse == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found\n");
    return(-4);
  }

  lecp->assertionConsumerServiceURL = lasso_authn_response_envelope_get_assertionConsumerServiceURL(
									LASSO_AUTHN_RESPONSE_ENVELOPE(lecp->response));
  if (lecp->assertionConsumerServiceURL == NULL){
    message(G_LOG_LEVEL_CRITICAL, "Assertion consumer service URL not found\n");
    return(-5);
  }

  return(0);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_lecp_finalize(LassoLecp *lecp)
{  
  debug("Lecp object 0x%x finalized ...\n", lecp);

  parent_class->finalize(G_OBJECT(lecp));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lecp_instance_init(LassoLecp *lecp)
{
  lecp->server                      = NULL;
  lecp->request                     = NULL;
  lecp->authnRequest                = NULL;
  lecp->response                    = NULL;
  lecp->authnResponse               = NULL;
  lecp->assertionConsumerServiceURL = NULL;
}

static void
lasso_lecp_class_init(LassoLecpClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->finalize = (void *)lasso_lecp_finalize;
}

GType lasso_lecp_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLecpClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lecp_class_init,
      NULL,
      NULL,
      sizeof(LassoLecp),
      0,
      (GInstanceInitFunc) lasso_lecp_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT,
				       "LassoLecp",
				       &this_info, 0);
  }
  return this_type;
}

LassoLecp *
lasso_lecp_new(LassoServer *server)
{
  LassoLecp *lecp;

  lecp = g_object_new(LASSO_TYPE_LECP, NULL);

  if(LASSO_IS_SERVER(server)){
    debug("Add server to lecp object\n");
    lecp->server = lasso_server_copy(server);
  }

  return(lecp);
}
