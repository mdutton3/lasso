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

#include <lasso/environs/logout.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

int
lasso_logout_build_request_msg(LassoLogout *logout)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* get the prototocol profile of the logout */
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    printf("provider not found\n");
    return(-1);
  }

  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);
  if(protocolProfile==NULL){
    printf("No protocol profile for logout request message\n");
    return(-2);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    profileContext->msg_url = lasso_provider_get_singleLogoutServiceUrl(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }

  return(0);
}

gint
lasso_logout_build_response_msg(LassoLogout *logout)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* get the prototocol profile of the logout */
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    return(-1);
  }

  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);
  if(protocolProfile==NULL){
    return(-2);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    profileContext->msg_url = lasso_provider_get_singleLogoutServiceUrl(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->response);
  }

  return(0);
}

gint
lasso_logout_init_request(LassoLogout *logout,
			  xmlChar     *remote_providerID)
{
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;
  LassoLogoutRequest  *request;

  xmlChar *content, *nameQualifier, *format;

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* get identity */
  identity = lasso_user_get_identity(profileContext->user, profileContext->remote_providerID);
  if(!identity)
    return(1);

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(logout->provider_type){
  case lassoProfileContextServiceProviderType:
    nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    break;
  case lassoProfileContextIdentityProviderType:
    /* get the next assertion ( next authenticated service provider ) */
    nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    break;
  }
  
  if(!nameIdentifier){
    printf("error, name identifier not found\n");
    return(2);
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier");
  format = lasso_node_get_attr_value(nameIdentifier, "Format");
  profileContext->request = lasso_logout_request_new(lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
						     content,
						     nameQualifier,
						     format);

  return(0);
}

gint
lasso_logout_handle_request(LassoLogout *logout, xmlChar *request_msg, gint request_method)
{
  LassoProfileContext *profileContext;
  xmlChar *statusCodeValue = lassoSamlStatusCodeSuccess;
  LassoNode *nameIdentifier;

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  switch(request_method){
  case lassoHttpMethodSoap:
    profileContext->request = lasso_logout_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    printf("TODO, implement the redirect method\n");
    break;
  case lassoHttpMethodGet:
    printf("TODO, implement the get method\n");
    break;
  default:
    printf("error while parsing the request\n");
    return(0);
  }

  /* set LogoutResponse */
  profileContext->response = lasso_logout_response_new(lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
						       statusCodeValue,
						       profileContext->request);

  /* Verify federation and */
  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
  if(lasso_user_verify_federation(profileContext->user, nameIdentifier)==FALSE){
    // TODO : implement a simple method to set the status code value
    
  }

  /* verify authentication (if ok, delete assertion) */
  if(lasso_user_verify_authentication(profileContext->user, nameIdentifier)==FALSE){
    // TODO : implement verify authentication
  }

  return(1);
}

gint
lasso_logout_handle_response(LassoLogout *logout, xmlChar *response_msg, gint response_method)
{
  LassoProfileContext *profileContext;

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* parse LogoutResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profileContext->response = lasso_logout_response_new_from_soap(response_msg);
  }
    
  /* verify status code value */
  // TODO : do the developer needs to get the value of the status code with the level 2 of lasso ?
  // node = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  // statusCodeValue = lasso_node_get_attr_value(node, "Value");
  
  return(0);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_instance_init(LassoLogout *logout){
}

static void
lasso_logout_class_init(LassoLogoutClass *klass) {
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
lasso_logout_new(LassoServer *server,
		 LassoUser   *user,
		 gint         provider_type)
{
  LassoLogout *logout;
  LassoProfileContext *profileContext;

  /* set the logout object */
  logout = g_object_new(LASSO_TYPE_LOGOUT, NULL);
  logout->provider_type = provider_type;

  /* set the properties */
  profileContext = LASSO_PROFILE_CONTEXT(logout);
  profileContext->user = user;
  profileContext->server = server;

  return(logout);
}
