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

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_logout_dump(LassoLogout *logout)
{
  gchar *dump = NULL;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);

  return(dump);
}

gint
lasso_logout_build_request_msg(LassoLogout *logout)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  
  profileContext = LASSO_PROFILE_CONTEXT(logout);

  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    message(G_LOG_LEVEL_ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  /* get the prototocol profile of the logout request */
  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);

  if(protocolProfile==NULL){
    message(G_LOG_LEVEL_ERROR, "Single Logout Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug("Building a soap request message\n");
    profileContext->request_type = lassoHttpMethodSoap;

    /* sign the request message */
    lasso_samlp_request_abstract_set_signature(LASSO_SAMLP_REQUEST_ABSTRACT(profileContext->request),
					       profileContext->server->signature_method,
					       profileContext->server->private_key,
					       profileContext->server->certificate);
    
    profileContext->msg_url  = lasso_provider_get_soapEndpoint(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    debug("Building a http get request message\n");
    profileContext->request_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_provider_get_singleLogoutServiceURL(provider);
    profileContext->msg_url = lasso_node_export_to_query(profileContext->request,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

gint
lasso_logout_build_response_msg(LassoLogout *logout)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  if(!LASSO_IS_LOGOUT(logout)){
    message(G_LOG_LEVEL_ERROR, "Not a Logout object\n");
    return(-1);
  }
  
  profileContext = LASSO_PROFILE_CONTEXT(logout);

  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    message(G_LOG_LEVEL_ERROR, "Provider not found %s\n", profileContext->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);
  if(protocolProfile==NULL){
    message(G_LOG_LEVEL_ERROR, "Single Logout Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug("Building a soap response message\n");
    profileContext->msg_url = NULL;
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->response);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    debug("Building a http get response message\n");
    profileContext->response_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->response,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
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
  LassoProfileContext *profileContext;
  gchar *current_provider_id;
  int i;


  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), NULL);

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* if a ProviderID from a SP request, pass it and return the next provider id found */
  for(i = 0; i<profileContext->user->assertion_providerIDs->len; i++){
    current_provider_id = g_strdup(g_ptr_array_index(profileContext->user->assertion_providerIDs, i));
    if(logout->first_remote_providerID!=NULL){
      if(xmlStrEqual(current_provider_id, logout->first_remote_providerID)){
	/* message(G_LOG_LEVEL_INFO, "It's the ProviderID of the SP requester (%s) : %s, pass it\n", logout->first_remote_providerID, current_provider_id); */
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
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  if(remote_providerID==NULL){
    /* message(G_LOG_LEVEL_INFO, "No remote provider id, get the next assertion peer provider id\n"); */
    profileContext->remote_providerID = lasso_user_get_next_assertion_remote_providerID(profileContext->user);
  }
  else{
    /* message(G_LOG_LEVEL_INFO, "A remote provider id for logout request : %s\n", remote_providerID); */
    profileContext->remote_providerID = g_strdup(remote_providerID);
  }

  if(profileContext->remote_providerID==NULL){
    message(G_LOG_LEVEL_ERROR, "No provider id for init request\n");
    return(-2);
  }

  /* get identity */
  identity = lasso_user_get_identity(profileContext->user, profileContext->remote_providerID);
  if(identity==NULL){
    message(G_LOG_LEVEL_ERROR, "Identity not found\n");
    return(-3);
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profileContext->provider_type){
  case lassoProviderTypeSp:
    nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    break;
  case lassoProviderTypeIdp:
    nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown provider type\n");
    return(-4);
  }
  
  if(!nameIdentifier){
    message(G_LOG_LEVEL_ERROR, "Name identifier not found for %s\n", profileContext->remote_providerID);
    return(-5);
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profileContext->request = lasso_logout_request_new(profileContext->server->providerID,
						     content,
						     nameQualifier,
						     format);

  if(profileContext->request==NULL){
    message(G_LOG_LEVEL_ERROR, "Error while creating the request\n");
    return(-6);
  }

  return(0);
}

gint lasso_logout_load_user_dump(LassoLogout *logout,
				 gchar       *user_dump)
{
  LassoProfileContext *profileContext;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(user_dump!=NULL, -1);

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  profileContext->user = lasso_user_new_from_dump(user_dump);

  return(0);
}

gint lasso_logout_load_request_msg(LassoLogout     *logout,
				   gchar           *request_msg,
				   lassoHttpMethods request_method)
{
  LassoProfileContext *profileContext;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(request_msg!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  switch(request_method){
  case lassoHttpMethodSoap:
    debug("Build a logout request from soap msg\n");
    profileContext->request = lasso_logout_request_new_from_export(request_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    debug("Build a logout request from query msg\n");
    profileContext->request = lasso_logout_request_new_from_export(request_msg, lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodGet:
    message(G_LOG_LEVEL_WARNING, "TODO, implement the get method\n");
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown request method\n");
    return(-3);
  }
  if(profileContext->request==NULL){
    message(G_LOG_LEVEL_ERROR, "Error while building the request from msg\n");
    return(-4);
  }

  /* get the NameIdentifier to load user dump */
  logout->nameIdentifier = lasso_node_get_child_content(profileContext->request,"NameIdentifier", NULL);

  return(0);
}

gint
lasso_logout_process_request(LassoLogout *logout)
{
  LassoProfileContext *profileContext;
  LassoIdentity *identity;
  LassoNode *nameIdentifier, *assertion;
  LassoNode *statusCode;
  LassoNodeClass *statusCode_class;
  xmlChar *remote_providerID;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  if(profileContext->request == NULL) {
    message(G_LOG_LEVEL_ERROR, "LogoutRequest not found\n");
    return(-1);
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  if(remote_providerID == NULL) {
    message(G_LOG_LEVEL_ERROR, "ProviderID in LogoutRequest not found\n");
    return(-1);
  }
  profileContext->remote_providerID = remote_providerID;

  /* set LogoutResponse */
  profileContext->response = lasso_logout_response_new(profileContext->server->providerID,
						       lassoSamlStatusCodeSuccess,
						       profileContext->request);
  if(profileContext->response == NULL) {
    message(G_LOG_LEVEL_ERROR, "Error while building response\n");
    return(-5);
  }

  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
  if(nameIdentifier == NULL) {
    message(G_LOG_LEVEL_ERROR, "Name identifier not found in logout request\n");
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-6);
  }

  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  if(remote_providerID == NULL) {
    message(G_LOG_LEVEL_ERROR, "Provider id not found in logout request\n");
    return(-7);
  }

  /* verify authentication */
  if(profileContext->user == NULL) {
    message(G_LOG_LEVEL_WARNING, "User environ not found\n");
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    return(-1);
  }

  assertion = lasso_user_get_assertion(profileContext->user, remote_providerID);
  if(assertion == NULL) {
    message(G_LOG_LEVEL_WARNING, "%s has no assertion\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    return(-8);
  }

  /* Verify federation */
  identity = lasso_user_get_identity(profileContext->user, remote_providerID);
  if(identity == NULL) {
    message(G_LOG_LEVEL_WARNING, "No identity for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-9);
  }

  if(lasso_identity_verify_nameIdentifier(identity, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-10);
  }

  /* verification is ok, save name identifier in logout object */
  switch(profileContext->provider_type) {
  case lassoProviderTypeSp:
    /* at sp, everything is ok, delete the assertion */
    lasso_user_remove_assertion(profileContext->user, profileContext->remote_providerID);
    break;
  case lassoProviderTypeIdp:
    /* if more than one sp registered, backup original infos of the sp requester */
    /* FIXME : get the nb of remote providers with a proper way */
    logout->first_remote_providerID = g_strdup(profileContext->remote_providerID);
    if(profileContext->user->assertion_providerIDs->len>1){
      logout->first_request = profileContext->request;
      profileContext->request = NULL;
    
      logout->first_response = profileContext->response;
      profileContext->response = NULL;

      profileContext->remote_providerID = NULL;    
    }

    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Uknown provider type\n");
  }

  return(0);
}

gint
lasso_logout_process_response_msg(LassoLogout      *logout,
				  gchar            *response_msg,
				  lassoHttpMethods  response_method)
{
  LassoProfileContext *profileContext;
  xmlChar   *statusCodeValue;
  LassoNode *statusCode;

  g_return_val_if_fail(LASSO_IS_LOGOUT(logout), -1);
  g_return_val_if_fail(response_msg!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* parse LogoutResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profileContext->response = lasso_logout_response_new_from_export(response_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    profileContext->response = lasso_logout_response_new_from_export(response_msg, lassoNodeExportTypeQuery);
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown response method\n");
    return(-3);
  }

  if(profileContext->response==NULL){
    message(G_LOG_LEVEL_ERROR, "LogoutResponse is NULL\n");
    return(-1);
  }
  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);

  if(statusCode==NULL){
    message(G_LOG_LEVEL_ERROR, "StatusCode node not found\n");
    return(-1);
  }

  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", NULL);

  if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)){
    return(-1);
  }

  profileContext->remote_providerID = lasso_node_get_child_content(profileContext->response, "ProviderID", NULL);
  /* response is ok, so delete the assertion */
  switch(profileContext->provider_type){
  case lassoProviderTypeSp:
    break;
  case lassoProviderTypeIdp:
    /* response os ok, delete the assertion */
    lasso_user_remove_assertion(profileContext->user, profileContext->remote_providerID);
    message(G_LOG_LEVEL_INFO, "Remove assertion for %s\n", profileContext->remote_providerID);

    /* if no more assertion for other providers, remove assertion of the original provider and restore the original requester infos */
    if(profileContext->user->assertion_providerIDs->len == 1){
      message(G_LOG_LEVEL_WARNING, "remove assertion of the original provider\n");
      lasso_user_remove_assertion(profileContext->user, logout->first_remote_providerID);

      profileContext->remote_providerID = logout->first_remote_providerID;
      profileContext->request = logout->first_request;
      profileContext->response = logout->first_response;
    }

    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unkown provider type\n");
  }

  return(0);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_logout_finalize(LassoLogout *logout)
{  
  debug("Logout object 0x%x finalized ...\n", logout);

  parent_class->finalize(G_OBJECT(logout));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_instance_init(LassoLogout *logout)
{
  logout->first_request = NULL;
  logout->first_response = NULL;
  logout->first_remote_providerID = NULL;
}

static void
lasso_logout_class_init(LassoLogoutClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
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
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoLogout",
				       &this_info, 0);
  }
  return this_type;
}

LassoLogout *
lasso_logout_new(lassoProviderTypes  provider_type,
		 LassoServer        *server,
		 LassoUser          *user)
{
  LassoLogout *logout;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the logout object */
  logout = g_object_new(LASSO_TYPE_LOGOUT,
			"provider_type", provider_type,
			"server", server,
			"user", user,
			NULL);

  return(logout);
}
