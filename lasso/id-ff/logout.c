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

xmlChar *lasso_logout_build_request(LassoLogout *logout){
     char          *protocolProfile;
     char          *message, *url, *query, *nameIdentifier, *nameQualifier, *format;
     LassoNode     *request, identifier;
     LassoProvider *provider;

     provider = lasso_server_find_provider(logout->server, logout->peer_providerID);
     if(!provider)
	  return(NULL);

     identifier = lasso_user_get_nameIdentifier_by_peer_providerID(logout->user, logout->peer_providerID);
     nameIdentifier = lasso_nameIdentifier_get_content(identifier);
     nameQualifier = lasso_nameIdentifier_get_nameQualifier(identifier);
     format = lasso_nameIdentifier_get_format(identifier);
     
     request = lasso_logout_request_new(logout->local_providerID,
					nameIdentifier,
					nameQualifier,
					format);
     if(!request)
	  return(NULL);

     url = lasso_provider_get_singleLogoutServiceUrl(provider);
     if(!url)
	  return(NULL);

     protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);
     if(!protocolProfile)
	  return(NULL);

     /* FIXME : do we need to store the url in the logout context ? */
     if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpHttp) ||
	xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpHttp)){
	  /* FIXME : use a constant instead a integer for the signature method */
	  query = lasso_node_export_to_query(logout->request, 0, logout->server->private_key);
          /* FIXME : use a more proper method to allocate the message ? */
	  message = (xmlChar *)malloc(strlen(url)+strlen(query)+2); /* +2 : ? and end of line */
	  sprintf(message , "%s?%s", url, query);
	  logout->request_protocol_method = lasso_protocol_method_redirect;
     }
     else if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) ||
	xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
	  message = lasso_node_exort_to_soap(logout->request);
	  logout->request_protocol_method = lasso_protocol_method_soap;
     }

     return(message);
}

xmlChar *lasso_logout_process_request(LassoLogout *logout,
				      gchar       *request,
				      gint         request_method){

     LassoNode     *nameIdentifier, *identity;
     LassoProvider *provider;
     char          *protocolProfile;
     xmlChar       *url, *query, *message;

     switch(request_method){
     case lasso_protocol_method_redirect:
	  logout->request = lasso_logout_request_new_from_query(request);
	  break;
     case lasso_protocol_method_soap:
	  logout->request = lasso_logout_request_new_from_soap(request);
	  break;
     default:
	  return(NULL);
     }

     logout->response = lasso_logout_response_new(logout->local_providerID, lassoSamlStatusCodeSuccess, logout->request);

     logout->peer_providerID = lasso_logout_request_get_providerID(logout->request);
     
     /* older and odd method : lasso_node_get_child(logout->request, "NameIdentifier", NULL); */
     nameIdentifier = lasso_logout_request_get_nameIdentifier(logout->request);

     if(!lasso_profile_context_verify_federation(logout->user, logout->peer_providerID, nameIdentifier)){
	  lasso_logout_response_set_statusCode_value(logout->response, lassoLibStatusCodeFederationDoesNotExist);
	  logout->response_status_code_value = lasso_status_response_federation_does_not_exists;
     }

     if(!lasso_logout_verify_authentication(logout->user, logout->peer_providerID, nameIdentifier)){
	  lasso_logout_response_set_statusCode_value(logout->response, lassoSamlStatusCodeRequestDenied);
	  logout->response_status_code_value = lasso_status_response_request_denied;
     }

     provider = lasso_server_find_provider(logout->server, logout->peer_providerID);
     if(!provider)
	  return(NULL);

     url = lasso_provider_get_singleLogoutProtocolServiceReturnUrl(provider);
     if(!url)
	  return(NULL);

     protocolProfile = lasso_provider_get_singleLogoutProtocolProfile(provider);
     if(!protocolProfile)
	  return(NULL);

     /* FIXME : do we need to store the url in the logout context ? */
     if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpHttp) ||
	xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpHttp)){
	  query = lasso_node_export_to_query(request, 0, NULL);
	  message = (char *)malloc(strlen(url)+strlen(query)+2); /* FIXME */
	  sprintf(message , "%s?%s", url, query);
	  logout->request_protocol_method = lasso_protocol_method_redirect;
     }
     else if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) ||
	xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
	  message = lasso_node_exort_to_soap(request);
	  logout->request_protocol_method = lasso_protocol_method_soap;
     }

     logout->response_status_code_value = lasso_status_response_success;

     return(message);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_instance_init(LassoLogout *logout){
}

static void
lasso_identity_class_init(LassoLogoutClass *klass) {
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
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLogout",
				       &this_info, 0);
  }
  return this_type;
}

LassoLogout*
lasso_logout_new()
{
  LassoLogout *logout;

  logout = g_object_new(LASSO_TYPE_LOGOUT, NULL);

  return(logout);
}
