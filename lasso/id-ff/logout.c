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

gchar *
lasso_logout_dump(LassoLogout *logout)
{
  LassoProfileContext *profileContext;
  gchar *dump;
}

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
    return(-1);
  }

  protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);
  if(protocolProfile==NULL){
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
			  gchar       *remote_providerID)
{
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;
  LassoLogoutRequest  *request;

  xmlChar *content, *nameQualifier, *format;

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* get identity */
  identity = lasso_user_get_identity(profileContext->user, profileContext->remote_providerID);
  if(identity==NULL)
    return(-1);

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
    return(-2);
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
lasso_logout_handle_request_msg(LassoLogout      *logout,
				gchar            *request_msg,
				lassoHttpMethods  request_method)
{
  LassoProfileContext *profileContext;
  LassoIdentity *identity;
  LassoNode *nameIdentifier, *assertion;
  xmlChar *remote_providerID;

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  switch(request_method){
  case lassoHttpMethodSoap:
    profileContext->request = lasso_logout_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    profileContext->request = lasso_logout_request_new_from_query(request_msg);
    break;
  case lassoHttpMethodGet:
    printf("TODO, implement the get method\n");
    break;
  default:
    printf("error while parsing the request\n");
    return(-1);
  }

  /* set LogoutResponse */
  profileContext->response = lasso_logout_response_new(lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
						       lassoSamlStatusCodeSuccess,
						       profileContext->request);

  nameIdentifier = lasso_logout_request_get_nameIdentifier(profileContext->response);
  if(nameIdentifier==NULL){
    return(-2);
  }

  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);

  /* Verify federation */
  identity = lasso_user_get_identity(profileContext->user, remote_providerID);
  if(identity==NULL){
    return(-3);
  }

  if(lasso_identity_verify_nameIdentifier(identity, nameIdentifier)==FALSE){
    return(-4);
  }

  /* verify authentication (if ok, delete assertion) */
  assertion = lasso_user_get_assertion(profileContext->user, remote_providerID);
  if(assertion==NULL){
    return(-5);
  }

  /* TODO : verify the name identifier */

  return(0);
}

gint
lasso_logout_handle_response_msg(LassoLogout *logout,
				 gchar *response_msg,
				 lassoHttpMethods response_method)
{
  LassoProfileContext *profileContext;
  xmlChar *statusCodeValue;

  profileContext = LASSO_PROFILE_CONTEXT(logout);

  /* parse LogoutResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profileContext->response = lasso_logout_response_new_from_soap(response_msg);
  }
    
  statusCodeValue = lasso_logout_response_get_statusCodeValue(profileContext->response);
  if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)){
    return(-1);
  }

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
