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

#include <lasso/environs/logout.h>

#define LASSO_LOGOUT_NODE            "LassoLogout"
#define LASSO_REMOTE_PROVIDERID_NODE "RemoteProviderID"

static GObjectClass *parent_class = NULL;

struct _LassoLogoutPrivate
{
  gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_logout_dump(LassoLogout *logout)
{
  gchar *dump = NULL;
  LassoNode *logout_node = NULL;
  LassoNodeClass *logout_class = NULL;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);

  logout_node = lasso_node_new();
  logout_class = LASSO_NODE_GET_CLASS(logout_node);
  logout_class->set_name(logout_node, LASSO_LOGOUT_NODE);

  /* back up */
/*   lasso_node_add_child(logout_node, logout->initial_request); */
/*   lasso_node_add_child(logout_node, logout->initial_response); */
/*   lasso_node_set_prop(logout_node, LASSO_REMOTE_PROVIDERID_NODE, logout->initial_remote_providerID); */

  return(dump);
}

gint
lasso_logout_build_request_msg(LassoLogout *logout)
{
  LassoProfile *profile;
  LassoProvider *provider;
  xmlChar *protocolProfile;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  
  profile = LASSO_PROFILE(logout);

  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID);
  if(provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider %s not found\n", profile->remote_providerID);
    return(-2);
  }

  /* get the prototocol profile of the logout request */
  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider,
								   lassoProviderTypeIdp,
								   NULL);

  if(protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Single Logout Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
     xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    debug("Building a soap request message\n");
    profile->request_type = lassoHttpMethodSoap;

    /* sign the request message */
    lasso_samlp_request_abstract_set_signature(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request),
					       profile->server->signature_method,
					       profile->server->private_key,
					       profile->server->certificate,
					       NULL);
    
    profile->msg_url  = lasso_provider_get_soapEndpoint(provider,
							lassoProviderTypeIdp,
							NULL);
    profile->msg_body = lasso_node_export_to_soap(profile->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	  xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    debug("Building a http get request message\n");
    profile->request_type = lassoHttpMethodRedirect;
    profile->msg_url = lasso_provider_get_singleLogoutServiceURL(provider,
								 lassoProviderTypeIdp,
								 NULL);
    profile->msg_url = lasso_node_export_to_query(profile->request,
						  profile->server->signature_method,
						  profile->server->private_key);
    profile->msg_body = NULL;
  }

  return(0);
}

gint
lasso_logout_build_response_msg(LassoLogout *logout)
{
  LassoProfile *profile;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  if(!LASSO_IS_LOGOUT(logout)){
    message(G_LOG_LEVEL_CRITICAL, "Not a Logout object\n");
    return(-1);
  }
  
  profile = LASSO_PROFILE(logout);

  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID);
  if(provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider not found %s\n", profile->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider,
								   lassoProviderTypeSp,
								   NULL);
  if(protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Single Logout Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
     xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    debug("Building a soap response message\n");
    profile->msg_url = NULL;
    profile->msg_body = lasso_node_export_to_soap(profile->response);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	  xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    debug("Building a http get response message\n");
    profile->response_type = lassoHttpMethodRedirect;
    profile->msg_url = lasso_node_export_to_query(profile->response,
						  profile->server->signature_method,
						  profile->server->private_key);
    profile->msg_body = NULL;
  }

  return(0);
}

void
lasso_logout_destroy(LassoLogout *logout)
{
  g_object_unref(G_OBJECT(logout));
}

gchar*
lasso_logout_get_next_providerID(LassoLogout *logout)
{
  LassoProfile *profile;
  gchar *current_provider_id;
  int i;


  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);

  profile = LASSO_PROFILE(logout);

  /* if a ProviderID from a SP request, pass it and return the next provider id found */
  for(i = 0; i<profile->session->providerIDs->len; i++){
    current_provider_id = g_strdup(g_ptr_array_index(profile->session->providerIDs, i));
    if(logout->initial_remote_providerID!=NULL){
      if(xmlStrEqual(current_provider_id, logout->initial_remote_providerID)){
	debug("It's the ProviderID of the SP requester (%s) : %s, pass it\n",
	      logout->initial_remote_providerID,
	      current_provider_id);
	xmlFree(current_provider_id);
	continue;
      }
    }
    return(current_provider_id);
  }

  return(NULL);
}

gint
lasso_logout_init_request(LassoLogout *logout,
			  gchar       *remote_providerID)
{
  LassoProfile    *profile;
  LassoNode       *nameIdentifier;
  LassoFederation *federation;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  profile = LASSO_PROFILE(logout);

  if(remote_providerID == NULL) {
    /* message(G_LOG_LEVEL_INFO, "No remote provider id, get the next assertion peer provider id\n"); */
    profile->remote_providerID = lasso_session_get_next_assertion_remote_providerID(profile->session);
  }
  else {
    /* message(G_LOG_LEVEL_INFO, "A remote provider id for logout request : %s\n", remote_providerID); */
    profile->remote_providerID = g_strdup(remote_providerID);
  }

  if(profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id for init request\n");
    return(-2);
  }

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    return(-3);
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profile->provider_type){
  case lassoProviderTypeSp:
    nameIdentifier = lasso_federation_get_local_nameIdentifier(federation);
    if(nameIdentifier == NULL) {
      nameIdentifier = lasso_federation_get_remote_nameIdentifier(federation);
    }
    break;
  case lassoProviderTypeIdp:
    nameIdentifier = lasso_federation_get_remote_nameIdentifier(federation);
    if(nameIdentifier == NULL) {
      nameIdentifier = lasso_federation_get_local_nameIdentifier(federation);
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    return(-4);
  }
  lasso_federation_destroy(federation);

  if(nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found for %s\n",
	    profile->remote_providerID);
    return(-5);
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier, NULL);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier",
					    NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profile->request = lasso_logout_request_new(profile->server->providerID,
					      content,
					      nameQualifier,
					      format);

  /* free the nameIdentifier infos except the value (keep in profile->nameIdentifier) */
  profile->nameIdentifier = content;

  xmlFree(nameQualifier);
  xmlFree(format);
  lasso_node_destroy(nameIdentifier);

  if(profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while creating the request\n");
    return(-6);
  }

  return(0);
}

gint lasso_logout_process_request_msg(LassoLogout     *logout,
				      gchar           *request_msg,
				      lassoHttpMethod  request_method)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(request_msg != NULL, -2);

  profile = LASSO_PROFILE(logout);

  switch(request_method) {
  case lassoHttpMethodSoap:
    debug("Build a logout request from soap msg\n");
    profile->request = lasso_logout_request_new_from_export(request_msg,
							    lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    debug("Build a logout request from query msg\n");
    profile->request = lasso_logout_request_new_from_export(request_msg,
							    lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodGet:
    debug("TODO, implement the get method\n");
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid request method\n");
    return(-3);
  }
  if(profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the request from msg\n");
    return(-4);
  }

  /* get the NameIdentifier to load identity dump */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier",
							 NULL, NULL);

  /* get the RelayState */
  profile->msg_relayState = lasso_node_get_child_content(profile->request,
							 "RelayState",
							 NULL, NULL);

  return(0);
}

gint
lasso_logout_validate_request(LassoLogout *logout)
{
  LassoProfile *profile;
  LassoFederation *federation;
  LassoNode *nameIdentifier, *assertion;
  LassoNode *statusCode;
  LassoNodeClass *statusCode_class;
  xmlChar *remote_providerID;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  profile = LASSO_PROFILE(logout);

  if(profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "LogoutRequest not found\n");
    return(-1);
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);
  if(remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "ProviderID in LogoutRequest not found\n");
    return(-1);
  }
  profile->remote_providerID = remote_providerID;

  /* set LogoutResponse */
  profile->response = lasso_logout_response_new(profile->server->providerID,
						lassoSamlStatusCodeSuccess,
						profile->request);
  if(profile->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building response\n");
    return(-5);
  }

  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profile->request, "NameIdentifier",
					NULL, NULL);
  if(nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in logout request\n");
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-6);
  }

  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);
  if(remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider id not found in logout request\n");
    return(-7);
  }

  /* verify authentication */
  if(profile->identity == NULL) {
    message(G_LOG_LEVEL_WARNING, "Identity not found\n");
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    return(-1);
  }

  assertion = lasso_session_get_assertion(profile->session, remote_providerID);
  if(assertion == NULL) {
    message(G_LOG_LEVEL_WARNING, "%s has no assertion\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    return(-8);
  }
  lasso_node_destroy(assertion);

  /* Verify federation */
  federation = lasso_identity_get_federation(profile->identity, remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_WARNING, "No federation for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-9);
  }

  if(lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-10);
  }
  lasso_federation_destroy(federation);

  /* verification is ok, save name identifier in logout object */
  lasso_session_remove_assertion(profile->session, profile->remote_providerID);
  if(profile->provider_type==lassoProviderTypeIdp){
    logout->initial_remote_providerID = g_strdup(profile->remote_providerID);
    if(profile->session->providerIDs->len>1){
      logout->initial_request = profile->request;
      profile->request = NULL;
      logout->initial_response = profile->response;
      profile->response = NULL;
      profile->remote_providerID = NULL;    
    }
  }

  return(0);
}

gint
lasso_logout_process_response_msg(LassoLogout     *logout,
				  gchar           *response_msg,
				  lassoHttpMethod  response_method)
{
  LassoProfile *profile;
  xmlChar   *statusCodeValue;
  LassoNode *statusCode;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(response_msg != NULL, -2);

  profile = LASSO_PROFILE(logout);

  /* parse LogoutResponse */
  switch(response_method) {
  case lassoHttpMethodSoap:
    profile->response = lasso_logout_response_new_from_export(response_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    profile->response = lasso_logout_response_new_from_export(response_msg, lassoNodeExportTypeQuery);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Unknown response method\n");
    return(-3);
  }

  if(profile->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "LogoutResponse is NULL\n");
    return(-1);
  }
  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);

  if(statusCode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "StatusCode node not found\n");
    return(-1);
  }

  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", NULL);

  if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)) {
    message(G_LOG_LEVEL_WARNING, "Status code value is not Success\n");
    return(-1);
  }

  profile->remote_providerID = lasso_node_get_child_content(profile->response, "ProviderID",
							    NULL, NULL);

  /* response os ok, delete the assertion */
  lasso_session_remove_assertion(profile->session, profile->remote_providerID);

  /* response is ok, so delete the assertion */
  switch(profile->provider_type) {
  case lassoProviderTypeSp:
    break;
  case lassoProviderTypeIdp:
    /* if no more assertion for other providers, remove assertion of the original provider and restore the original requester infos */
    if(profile->session->providerIDs->len == 1){
      lasso_session_remove_assertion(profile->session, logout->initial_remote_providerID);

      profile->remote_providerID = logout->initial_remote_providerID;
      profile->request = logout->initial_request;
      profile->response = logout->initial_response;
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
  }

  return(0);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_logout_dispose(LassoLogout *logout)
{
  if (logout->private->dispose_has_run) {
    return;
  }
  logout->private->dispose_has_run = TRUE;

  debug("Logout object 0x%x disposed ...\n", logout);

  /* unref reference counted objects */
  lasso_node_destroy(logout->initial_request);
  lasso_node_destroy(logout->initial_response);

  parent_class->dispose(G_OBJECT(logout));
}

static void
lasso_logout_finalize(LassoLogout *logout)
{  
  debug("Logout object 0x%x finalized ...\n", logout);

  g_free(logout->initial_remote_providerID);

  g_free(logout->private);

  parent_class->finalize(G_OBJECT(logout));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_instance_init(GTypeInstance   *instance,
			   gpointer         g_class)
{
  LassoLogout *logout = LASSO_LOGOUT(instance);

  logout->private = g_new (LassoLogoutPrivate, 1);
  logout->private->dispose_has_run = FALSE;

  logout->initial_request = NULL;
  logout->initial_response = NULL;
  logout->initial_remote_providerID = NULL;
}

static void
lasso_logout_class_init(LassoLogoutClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_logout_dispose;
  gobject_class->finalize = (void *)lasso_logout_finalize;
}

GType lasso_logout_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLogoutClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_logout_class_init,
      NULL,
      NULL,
      sizeof(LassoLogout),
      0,
      (GInstanceInitFunc) lasso_logout_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoLogout",
				       &this_info, 0);
  }
  return this_type;
}

LassoLogout *
lasso_logout_new(LassoServer       *server,
		 lassoProviderType  provider_type)
{
  LassoLogout *logout;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the logout object */
  logout = g_object_new(LASSO_TYPE_LOGOUT,
			"server", lasso_server_copy(server),
			"provider_type", provider_type,
			NULL);

  return(logout);
}
