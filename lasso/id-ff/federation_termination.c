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
  LassoProfile  *profile;
  LassoProvider *provider;
  xmlChar       *protocolProfile;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);
  
  profile = LASSO_PROFILE(defederation);

  provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
  if(provider == NULL) {
    message(G_LOG_LEVEL_ERROR, "Provider %s not found\n", profile->remote_providerID);
    return(-2);
  }

  /* get the prototocol profile of the federation termination notification */
  protocolProfile = lasso_provider_get_federationTerminationNotificationProtocolProfile(provider);
  if(protocolProfile == NULL) {
    message(G_LOG_LEVEL_ERROR, "Federation termination notification protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
     xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    profile->request_type = lassoHttpMethodSoap;
    profile->msg_url = lasso_provider_get_federationTerminationServiceURL(provider);
    if(profile->msg_url == NULL) {
      message(G_LOG_LEVEL_ERROR, "Federation Termination Notification url not found\n");
      return(-4);
    }
    profile->msg_body = lasso_node_export_to_soap(profile->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	  xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    profile->request_type = lassoHttpMethodRedirect;
    profile->msg_url = lasso_node_export_to_query(profile->request,
						  profile->server->signature_method,
						  profile->server->private_key);
    profile->msg_body = NULL;
  }
  else{
    message(G_LOG_LEVEL_ERROR, "Invalid protocol profile\n");
    return(-5);
  }

  return(0);
}

void
lasso_federation_termination_destroy(LassoFederationTermination *defederation)
{
  g_object_unref(G_OBJECT(defederation));
}

gint
lasso_federation_termination_init_notification(LassoFederationTermination *defederation,
					       gchar                      *remote_providerID)
{
  LassoProfile *profile;
  LassoFederation       *federation;

  LassoNode *nameIdentifier = NULL;
  xmlChar   *content = NULL, *nameQualifier = NULL, *format = NULL;

  gint codeError = 0;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);

  profile = LASSO_PROFILE(defederation);

  if (remote_providerID == NULL) {
    message(G_LOG_LEVEL_INFO, "No remote provider id, get the remote provider id of the first federation\n");
    profile->remote_providerID = lasso_identity_get_next_federation_remote_providerID(profile->identity);
  }
  else {
    message(G_LOG_LEVEL_INFO, "A remote provider id for defederation notification : %s\n", remote_providerID);
    profile->remote_providerID = g_strdup(remote_providerID);
  }

  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_ERROR, "No provider Id for init notification\n");
    codeError = -1;
    goto done;
  }

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_ERROR, "Federation not found for %s\n", profile->remote_providerID);
    codeError = -1;
    goto done;
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profile->provider_type) {
  case lassoProviderTypeSp:
    nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
    if(!nameIdentifier) {
      nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
    }
    break;
  case lassoProviderTypeIdp:
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
    if(!nameIdentifier) {
      nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
    }
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Invalid provider type\n");
  }
  
  if(!nameIdentifier) {
    message(G_LOG_LEVEL_ERROR, "Name identifier not found for %s\n", profile->remote_providerID);
    codeError = -1;
    goto done;
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profile->request = lasso_federation_termination_notification_new(profile->server->providerID,
								   content,
								   nameQualifier,
								   format);

  if(profile->request == NULL) {
    message(G_LOG_LEVEL_ERROR, "Error while creating the notification\n");
    codeError = -1;
    goto done;
  }

  done:
  /* destroy allocated objects */
  debug("Free content, nameQualifier, format and nameIdentifier vars\n");
  xmlFree(content);
  xmlFree(nameQualifier);
  xmlFree(format);
  lasso_node_destroy(nameIdentifier);

  return(codeError);
}

gint
lasso_federation_termination_load_notification_msg(LassoFederationTermination *defederation,
						   gchar                      *notification_msg,
						   lassoHttpMethods            notification_method)
{
  LassoProfile *profile;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);
  g_return_val_if_fail(notification_msg!=NULL, -2);

  profile = LASSO_PROFILE(defederation);

  switch(notification_method){
  case lassoHttpMethodSoap:
    debug("Build a federation termination notification from soap msg\n");
    profile->request = lasso_federation_termination_notification_new_from_export(notification_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    debug("Build a federation termination notification from query msg\n");
    profile->request = lasso_federation_termination_notification_new_from_export(notification_msg, lassoNodeExportTypeQuery);
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Invalid notification method\n");
    return(-3);
  }
  if(profile->request==NULL){
    message(G_LOG_LEVEL_ERROR, "Error while building the notification from msg\n");
    return(-4);
  }

  /* get the NameIdentifier to load identity dump */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier", NULL);
  
  /* get the RelayState */
  profile->msg_relayState = lasso_node_get_child_content(profile->request,
							 "RelayState", NULL);

  return(0);
}

gint
lasso_federation_termination_process_notification(LassoFederationTermination *defederation)
{
  LassoProfile *profile;
  LassoFederation       *federation;
  LassoNode           *nameIdentifier;

  profile = LASSO_PROFILE(defederation);

  if(profile->request == NULL){
    message(G_LOG_LEVEL_ERROR, "Request not found\n");
    return(-1);
  }

  /* set the remote provider id from the request */
  profile->remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID", NULL);
  if(profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_ERROR, "Remote provider id not found\n");
    return(-1);
  }

  nameIdentifier = lasso_node_get_child(profile->request, "NameIdentifier", NULL);
  if(nameIdentifier == NULL) {
    message(G_LOG_LEVEL_ERROR, "Name identifier not found in request\n");
    return(-1);
  }

  /* Verify federation */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_ERROR, "Identity environ not found\n");
    return(-1);
  }

  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_WARNING, "No federation for %s\n", profile->remote_providerID);
    return(-1);
  }

  if (lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", profile->remote_providerID);
    return(-1);
  }

  /* remove federation of the remote provider */
  lasso_identity_remove_federation(profile->identity, profile->remote_providerID);

  return(0);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_federation_termination_instance_init(LassoFederationTermination *defederation)
{
}

static void
lasso_federation_termination_class_init(LassoFederationTerminationClass *class)
{
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
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoFederationTermination",
				       &this_info, 0);
  }
  return this_type;
}

LassoFederationTermination*
lasso_federation_termination_new(LassoServer *server,
				 gint         provider_type)
{
  LassoFederationTermination *defederation;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the federation_termination object */
  defederation = g_object_new(LASSO_TYPE_FEDERATION_TERMINATION,
			      "server", lasso_server_copy(server),
			      "provider_type", provider_type,
			      NULL);

  return(defederation);
}
