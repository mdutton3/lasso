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

#include <lasso/environs/federation_termination.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_federation_termination_build_notification_msg(LassoFederationTermination *defederation)
{
  LassoProfileContext *profileContext;
  LassoProvider       *provider;
  xmlChar             *protocolProfile;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);
  
  profileContext = LASSO_PROFILE_CONTEXT(defederation);

  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    message(G_LOG_LEVEL_ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  /* get the prototocol profile of the federation termination notification */
  protocolProfile = lasso_provider_get_federationTerminationNotificationProtocolProfile(provider);
  if(protocolProfile==NULL){
    message(G_LOG_LEVEL_ERROR, "Federation termination notification protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    profileContext->request_type = lassoHttpMethodSoap;
    profileContext->msg_url = lasso_provider_get_federationTerminationServiceURL(provider);
    if(profileContext->msg_url==NULL){
      message(G_LOG_LEVEL_ERROR, "Federation Termination Notification url not found\n");
      return(-4);
    }
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    profileContext->request_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->request,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }
  else{
    message(G_LOG_LEVEL_ERROR, "Unknown protocol profile\n");
    return(-5);
  }

  return(0);
}

void
lasso_federation_termination_destroy(LassoFederationTermination *defederation)
{
  g_object_unref(G_OBJECT(defederation));
}

gchar *
lasso_federation_termination_dump(LassoFederationTermination *defederation)
{
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), NULL);

  return(dump);
}

gint
lasso_federation_termination_init_notification(LassoFederationTermination *defederation,
					       gchar                      *remote_providerID)
{
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);

  profileContext = LASSO_PROFILE_CONTEXT(defederation);

  if (remote_providerID == NULL) {
    message(G_LOG_LEVEL_INFO, "No remote provider id, get the remote provider id of the first identity\n");
    profileContext->remote_providerID = lasso_user_get_next_identity_remote_providerID(profileContext->user);
  }
  else {
    message(G_LOG_LEVEL_INFO, "A remote provider id for defederation notification : %s\n", remote_providerID);
    profileContext->remote_providerID = g_strdup(remote_providerID);
  }

  if (profileContext->remote_providerID == NULL) {
    message(G_LOG_LEVEL_ERROR, "No provider Id for init notification\n");
    return(-2);
  }

  /* get identity */
  identity = lasso_user_get_identity(profileContext->user, profileContext->remote_providerID);
  if (identity == NULL) {
    message(G_LOG_LEVEL_ERROR, "Identity not found for %s\n", profileContext->remote_providerID);
    return(-2);
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profileContext->provider_type){
  case lassoProviderTypeSp:
    nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    if(!nameIdentifier){
      nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    }
    break;
  case lassoProviderTypeIdp:
    nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown provider type\n");
  }
  
  if(!nameIdentifier){
    message(G_LOG_LEVEL_ERROR, "Name identifier not found for %s\n", profileContext->remote_providerID);
    return(-3);
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profileContext->request = lasso_federation_termination_notification_new(profileContext->server->providerID,
									  content,
									  nameQualifier,
									  format);
  if(profileContext->request==NULL){
    message(G_LOG_LEVEL_ERROR, "Error while creating the notification\n");
    return(-6);
  }


  return(0);
}

gint
lasso_federation_termination_process_notification_msg(LassoFederationTermination *defederation,
						      gchar                      *request_msg,
						      lassoHttpMethods            request_method)
{
  LassoProfileContext *profileContext;
  LassoIdentity       *identity;
  LassoNode           *nameIdentifier;
  xmlChar             *remote_providerID;

  profileContext = LASSO_PROFILE_CONTEXT(defederation);

  switch(request_method){
  case lassoHttpMethodSoap:
    message(G_LOG_LEVEL_DEBUG, "Process a federation termination notification soap msg\n");
    profileContext->request = lasso_federation_termination_notification_new_from_export(request_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    message(G_LOG_LEVEL_DEBUG, "Process a federation termination notification query msg\n");
    profileContext->request = lasso_federation_termination_notification_new_from_export(request_msg, lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodGet:
    message(G_LOG_LEVEL_WARNING, "Implement the get federation termination notification method\n");
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown request method (%d)\n", request_method);
    return(-1);
  }
  if(profileContext->request==NULL){
    message(G_LOG_LEVEL_ERROR, "Error While building the request from msg\n");
    return(-1);
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  profileContext->remote_providerID = remote_providerID;

  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
  if (nameIdentifier == NULL) {
    message(G_LOG_LEVEL_ERROR, "Name identifier not found\n");
    return(-2);
  }

  /* Verify federation */
  if (profileContext->user == NULL){
    message(G_LOG_LEVEL_ERROR, "User environ not found\n");
    return(-3);
  }

  identity = lasso_user_get_identity(profileContext->user, remote_providerID);
  if (identity == NULL) {
    message(G_LOG_LEVEL_WARNING, "No identity for %s\n", remote_providerID);
    return(-4);
  }

  if (lasso_identity_verify_nameIdentifier(identity, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", remote_providerID);
    return(-5);
  }

  /* remove federation of the remote provider */
  lasso_identity_remove_remote_nameIdentifier(identity);
  message(G_LOG_LEVEL_INFO, "Remote name identifier removed from federation with %s\n",
	profileContext->remote_providerID);

  return(0);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_federation_termination_instance_init(LassoFederationTermination *defederation){
}

static void
lasso_federation_termination_class_init(LassoFederationTerminationClass *klass) {
}

GType lasso_federation_termination_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoFederationTerminationClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_federation_termination_class_init,
      NULL,
      NULL,
      sizeof(LassoFederationTermination),
      0,
      (GInstanceInitFunc) lasso_federation_termination_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoFederationTermination",
				       &this_info, 0);
  }
  return this_type;
}

LassoFederationTermination *
lasso_federation_termination_new(LassoServer *server,
				 LassoUser   *user,
				 gint         provider_type)
{
  LassoFederationTermination *defederation;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(LASSO_IS_USER(user), NULL);

  /* set the federation_termination object */
  defederation = g_object_new(LASSO_TYPE_FEDERATION_TERMINATION,
			      "server", server,
			      "user", user,
			      "provider_type", provider_type,
			      NULL);

  return(defederation);
}
