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
lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp)
{
  LassoProfile *profile;
  gchar *assertionConsumerServiceURL;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);

  assertionConsumerServiceURL = lasso_provider_get_assertionConsumerServiceURL(LASSO_PROVIDER(profile->server),
									       lassoProviderTypeSp,
									       NULL);
  if (assertionConsumerServiceURL == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found\n");
    return(-1);
  }

  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found\n");
    return(-1);
  }

  lecp->authnRequestEnvelope = lasso_authn_request_envelope_new(LASSO_AUTHN_REQUEST(profile->request),
								profile->server->providerID,
								assertionConsumerServiceURL);
  if (lecp->authnRequestEnvelope == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building AuthnRequestEnvelope\n");
    return(-1);
  }

  profile->msg_body = lasso_node_export(lecp->authnRequestEnvelope);
  if (profile->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnRequestEnvelope to POST msg\n");
    return(-1);
  }

  return(0);
}

gint
lasso_lecp_build_authn_request_msg(LassoLecp   *lecp,
				   const gchar *remote_providerID)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);
  
  profile->msg_url  = NULL; /* FIXME use remote_providerID to get url */
  profile->msg_body = lasso_node_export_to_soap(profile->request);
  if (profile->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the AuthnRequest SOAP message\n");
    return(-1);
  }

  return(0);
}

gint
lasso_lecp_build_authn_response_msg(LassoLecp   *lecp)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);
  profile->msg_url = g_strdup(lecp->assertionConsumerServiceURL);
  if (profile->msg_url == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found\n");
    return(-1);
  }
  profile->msg_body = lasso_node_export_to_base64(profile->response);
  if (profile->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse Base64 msg not found\n");
    return(-1);
  }

  return(0);
}

gint
lasso_lecp_build_authn_response_envelope_msg(LassoLecp   *lecp,
					     gint         authentication_result,
					     const gchar *authenticationMethod,
					     const gchar *reauthenticateOnOrAfter)
{
  LassoProfile  *profile;
  LassoProvider *provider;
  gchar         *assertionConsumerServiceURL;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);

  if (LASSO_IS_AUTHN_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found\n");
    return(-1);
  }

  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider %s not found\n", profile->remote_providerID);
    return(-1);
  }

  /* build lib:AuthnResponse */
  lasso_login_build_authn_response_msg(LASSO_LOGIN(lecp),
				       authentication_result,
				       authenticationMethod,
				       reauthenticateOnOrAfter);
  
  assertionConsumerServiceURL = lasso_provider_get_assertionConsumerServiceURL(provider,
									       lassoProviderTypeSp,
									       NULL);
  if (assertionConsumerServiceURL == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found\n");
    return(-1);
  }

  xmlFree(LASSO_PROFILE(lecp)->msg_body);
  LASSO_PROFILE(lecp)->msg_body = NULL;
  xmlFree(LASSO_PROFILE(lecp)->msg_url);
  LASSO_PROFILE(lecp)->msg_url = NULL;
  lecp->authnResponseEnvelope = lasso_authn_response_envelope_new(LASSO_AUTHN_RESPONSE(profile->response),
								  assertionConsumerServiceURL);
  LASSO_PROFILE(lecp)->msg_body = lasso_node_export_to_soap(lecp->authnResponseEnvelope);

  if (LASSO_PROFILE(lecp)->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnResponseEnvelope to SOAP msg\n");
    return(-1);
  }

  return(0);
}

gint
lasso_lecp_init_authn_request(LassoLecp *lecp)
{
  gint res;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  res = lasso_login_init_authn_request(LASSO_LOGIN(lecp));

  return(res);
}

gint
lasso_lecp_init_from_authn_request_msg(LassoLecp       *lecp,
				       gchar           *authn_request_msg,
				       lassoHttpMethod  authn_request_method)
{
  gint res;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(authn_request_msg!=NULL, -1);

  if (authn_request_method != lassoHttpMethodSoap) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid authentication request method\n");
    return(-1);
  }
  res = lasso_login_init_from_authn_request_msg(LASSO_LOGIN(lecp), authn_request_msg, authn_request_method);
  return(res);
}

gint
lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp,
					      gchar     *request_msg)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(request_msg!=NULL, -1);

  lecp->authnRequestEnvelope = lasso_authn_request_envelope_new_from_export(request_msg, lassoNodeExportTypeXml);
  if (lecp->authnRequestEnvelope == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the authentication request envelope\n");
    return(-1);
  }

  LASSO_PROFILE(lecp)->request = lasso_authn_request_envelope_get_authnRequest(LASSO_AUTHN_REQUEST_ENVELOPE(lecp->authnRequestEnvelope));
  if (LASSO_PROFILE(lecp)->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found\n");
    return(-1);
  }

  return(0);
}

gint
lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp,
					       gchar      *response_msg)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(response_msg!=NULL, -2);

  profile = LASSO_PROFILE(lecp);

  lecp->authnResponseEnvelope = lasso_authn_response_envelope_new_from_export(response_msg, lassoNodeExportTypeSoap);
  if (lecp->authnResponseEnvelope == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building AuthnResponseEnvelope\n");
    return(-1);
  }

  profile->response = lasso_authn_response_envelope_get_authnResponse(LASSO_AUTHN_RESPONSE_ENVELOPE(lecp->authnResponseEnvelope));
  if (profile->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found\n");
    return(-1);
  }

  lecp->assertionConsumerServiceURL = lasso_authn_response_envelope_get_assertionConsumerServiceURL(
    LASSO_AUTHN_RESPONSE_ENVELOPE(lecp->authnResponseEnvelope));
  if (lecp->assertionConsumerServiceURL == NULL){
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found\n");
    return(-1);
  }

  return(0);
}

void
lasso_lecp_destroy(LassoLecp *lecp)
{
  g_object_unref(G_OBJECT(lecp));
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
  lecp->authnRequestEnvelope        = NULL;
  lecp->authnResponseEnvelope       = NULL;
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
    
    this_type = g_type_register_static(LASSO_TYPE_LOGIN,
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

  if (LASSO_IS_SERVER(server)) {
    debug("Add server to lecp object\n");
    LASSO_PROFILE(lecp)->server = lasso_server_copy(server);
  }
      

  return(lecp);
}
