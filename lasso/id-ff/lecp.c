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

  assertionConsumerServiceURL = lasso_provider_get_metadata_one(
		  LASSO_PROVIDER(profile->server), "AssertionConsumerServiceURL");
  if (assertionConsumerServiceURL == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found");
    return -1;
  }

  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found");
    return -1;
  }

#if 0
  lecp->authnRequestEnvelope = lasso_authn_request_envelope_new(
		  LASSO_LIB_AUTHN_REQUEST(profile->request),
		  LASSO_PROVIDER(profile->server)->ProviderID,
		  assertionConsumerServiceURL);
#endif
  if (lecp->authnRequestEnvelope == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building AuthnRequestEnvelope");
    return -1;
  }

#if 0 /* XXX: dump to xml ? */
  profile->msg_body = lasso_node_export(lecp->authnRequestEnvelope);
#endif
  if (profile->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnRequestEnvelope to POST msg");
    return -1;
  }

  return 0;
}

/**
 * lasso_lecp_build_authn_request_msg:
 * @lecp: a LassoLecp
 * @remote_providerID: the providerID of the identity provider. When NULL, the first
 *                     identity provider is used.
 * 
 * Builds an authentication request. The data for the sending of the request are
 * stored in msg_url and msg_body (SOAP POST).
 * 
 * Return value: 0 on success and a negative value otherwise.
 **/
gint
lasso_lecp_build_authn_request_msg(LassoLecp   *lecp,
				   const gchar *remote_providerID)
{
  LassoProfile *profile;
  LassoProvider *remote_provider;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);
  if (remote_providerID == NULL) {
/*     profile->remote_providerID = lasso_server_get_first_providerID(profile->server); */
  }
  else {
    profile->remote_providerID = g_strdup(remote_providerID);
  }

  remote_provider = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);

  profile->msg_url  = lasso_provider_get_metadata_one(remote_provider, "SingleSignOnServiceURL");
  profile->msg_body = lasso_node_export_to_soap(profile->request, NULL, NULL);
  if (profile->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the AuthnRequest SOAP message");
    return -1;
  }

  return 0;
}

gint
lasso_lecp_build_authn_response_msg(LassoLecp *lecp)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);
  profile->msg_url = g_strdup(lecp->assertionConsumerServiceURL);
  if (profile->msg_url == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found");
    return -1;
  }
  profile->msg_body = lasso_node_export_to_base64(profile->response);
  if (profile->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse Base64 msg not found");
    return -1;
  }

  return 0;
}

gint
lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp,
		gint authentication_result,
		gboolean     is_consent_obtained,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter)
{
  LassoProfile  *profile;
  LassoProvider *provider;
  gchar         *assertionConsumerServiceURL;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  profile = LASSO_PROFILE(lecp);

  if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found");
    return -1;
  }

  provider = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider %s not found", profile->remote_providerID);
    return -1;
  }

  /* build lib:AuthnResponse */
  lasso_login_build_authn_response_msg(LASSO_LOGIN(lecp),
				       authentication_result,
				       is_consent_obtained,
				       authenticationMethod,
				       authenticationInstant,
				       reauthenticateOnOrAfter,
				       notBefore,
				       notOnOrAfter);
  
  assertionConsumerServiceURL = lasso_provider_get_metadata_one(
		  provider, "AssertionConsumerServiceURL");
  if (assertionConsumerServiceURL == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found");
    return -1;
  }

  xmlFree(LASSO_PROFILE(lecp)->msg_body);
  LASSO_PROFILE(lecp)->msg_body = NULL;
  xmlFree(LASSO_PROFILE(lecp)->msg_url);
  LASSO_PROFILE(lecp)->msg_url = NULL;
  lecp->authnResponseEnvelope = lasso_lib_authn_response_envelope_new(
		  LASSO_LIB_AUTHN_RESPONSE(profile->response),
		  assertionConsumerServiceURL);
  LASSO_PROFILE(lecp)->msg_body = lasso_node_export_to_soap(lecp->authnResponseEnvelope, NULL, NULL);

  if (LASSO_PROFILE(lecp)->msg_body == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while exporting the AuthnResponseEnvelope to SOAP msg");
    return -1;
  }

  return 0;
}

gint
lasso_lecp_init_authn_request(LassoLecp *lecp)
{
  gint res;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

  /* FIXME : BAD usage of http_method
     using POST method so that the lib:AuthnRequest is initialize with
     a signature template */
  res = lasso_login_init_authn_request(LASSO_LOGIN(lecp), LASSO_HTTP_METHOD_POST);

  return res;
}

gint
lasso_lecp_process_authn_request_msg(LassoLecp       *lecp,
				     gchar           *authn_request_msg)
{
  lassoHttpMethod  authn_request_method = 0; /* XXX: update to CVS */
  gint res;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(authn_request_msg!=NULL, -1);

  if (authn_request_method != LASSO_HTTP_METHOD_SOAP) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid authentication request method");
    return -1;
  }
  res = lasso_login_process_authn_request_msg(LASSO_LOGIN(lecp), authn_request_msg);
  return res;
}

gint
lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp,
					      gchar     *request_msg)
{
  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(request_msg!=NULL, -1);

#if 0 /* XXX */
  lecp->authnRequestEnvelope = lasso_authn_request_envelope_new_from_export(request_msg, LASSO_NODE_EXPORT_TYPE_XML);
#endif
  if (lecp->authnRequestEnvelope == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the authentication request envelope");
    return -1;
  }

#if 0
  LASSO_PROFILE(lecp)->request = lasso_authn_request_envelope_get_authnRequest(LASSO_AUTHN_REQUEST_ENVELOPE(lecp->authnRequestEnvelope));
#endif
  if (LASSO_PROFILE(lecp)->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found");
    return -1;
  }

  return 0;
}

gint
lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp,
					       gchar      *response_msg)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
  g_return_val_if_fail(response_msg!=NULL, -2);

  profile = LASSO_PROFILE(lecp);

  lecp->authnResponseEnvelope = lasso_lib_authn_response_envelope_new(NULL, NULL);
  lasso_node_init_from_message(lecp->authnResponseEnvelope, response_msg);
  if (lecp->authnResponseEnvelope == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building AuthnResponseEnvelope");
    return -1;
  }

#if 0 /* XXX */
  profile->response = lasso_authn_response_envelope_get_authnResponse(LASSO_AUTHN_RESPONSE_ENVELOPE(lecp->authnResponseEnvelope));
  if (profile->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found");
    return -1;
  }
#endif

#if 0 /* XXX */
  lecp->assertionConsumerServiceURL = lasso_authn_response_envelope_get_assertionConsumerServiceURL(
    LASSO_AUTHN_RESPONSE_ENVELOPE(lecp->authnResponseEnvelope));
  if (lecp->assertionConsumerServiceURL == NULL){
    message(G_LOG_LEVEL_CRITICAL, "AssertionConsumerServiceURL not found");
    return -1;
  }
#endif

  return 0;
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
  debug("Lecp object 0x%x finalized ...", lecp);

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
    debug("Add server to lecp object");
    /* XXX LASSO_PROFILE(lecp)->server = lasso_server_copy(server); */
  }
      

  return lecp;
}
