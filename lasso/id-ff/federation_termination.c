/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

gchar *
lasso_federation_termination_dump(LassoFederationTermination *federationTermination)
{
  LassoProfileContext *profileContext;
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(federationTermination), NULL);

  return(dump);
}

gint
lasso_federation_termination_build_notification_msg(LassoFederationTermination *federationTermination)
{
  LassoProfileContext *profileContext;
  LassoProvider       *provider;
  xmlChar             *protocolProfile;

  //g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(notification), NULL);
  
  profileContext = LASSO_PROFILE_CONTEXT(federationTermination);

  /* get the prototocol profile of the federation termination notification */
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-1);
  }

  protocolProfile = lasso_provider_get_federationTerminationNotificationProtocolProfile(provider);
  if(protocolProfile==NULL){
    debug(ERROR, "Single Federation_Termination Protocol profile not found\n");
    return(-2);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug(DEBUG, "building a soap federationTermination message\n");
    profileContext->request_type = lassoHttpMethodSoap;
    profileContext->msg_url = lasso_provider_get_federationTerminationNotificationServiceURL(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    debug(DEBUG, "building a http get federationTermination message\n");
    profileContext->request_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->request,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

gint
lasso_federation_termination_init_request(LassoFederationTermination *notification,
					  gchar                      *remote_providerID)
{
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(notification), -1);

  profileContext = LASSO_PROFILE_CONTEXT(notification);

  profileContext->remote_providerID = remote_providerID;

  /* get identity */
  identity = lasso_user_get_identity(profileContext->user, profileContext->remote_providerID);
  if(identity==NULL){
    debug(ERROR, "error, identity not found\n");
    return(-2);
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profileContext->provider_type){
  case lassoProviderTypeSp:
    nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    break;
  case lassoProviderTypeIdp:
    /* get the next assertion ( next authenticated service provider ) */
    nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    break;
  }
  
  if(!nameIdentifier){
    debug(ERROR, "error, name identifier not found\n");
    return(-3);
  }
  debug(DEBUG, "name identifier : %s\n", lasso_node_export(nameIdentifier));

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier");
  format = lasso_node_get_attr_value(nameIdentifier, "Format");
  profileContext->request = lasso_federation_termination_notification_new(
							  lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
							  content,
							  nameQualifier,
							  format);

  return(0);
}

gint
lasso_federation_termination_handle_request_msg(LassoFederationTermination *notification,
						gchar                      *request_msg,
						lassoHttpMethods            request_method)
{
  LassoProfileContext *profileContext;
  LassoIdentity *identity;
  LassoNode *nameIdentifier, *assertion;
  LassoNode *statusCode;
  LassoNodeClass *statusCode_class;
  xmlChar *remote_providerID;

  profileContext = LASSO_PROFILE_CONTEXT(notification);

  switch(request_method){
  case lassoHttpMethodSoap:
    debug(DEBUG, "build a federation termination notification from soap msg\n");
    profileContext->request = lasso_federation_termination_notification_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    debug(DEBUG, "build a federation termination notification from query msg\n");
    profileContext->request = lasso_federation_termination_notification_new_from_query(request_msg);
    break;
  case lassoHttpMethodGet:
    debug(WARNING, "TODO, implement the get federation termination notification method\n");
    break;
  default:
    debug(ERROR, "Unknown request method\n");
    return(-1);
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  profileContext->remote_providerID = remote_providerID;

  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
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

  return(0);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_federation_termination_instance_init(LassoFederationTermination *notification){
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
  LassoFederationTermination *notification;
  LassoProfileContext *profileContext;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(LASSO_IS_USER(user), NULL);

  /* set the federation_termination object */
  notification = g_object_new(LASSO_TYPE_FEDERATION_TERMINATION, NULL);

  /* set the properties */
  profileContext = LASSO_PROFILE_CONTEXT(notification);
  profileContext->user = user;
  profileContext->server = server;
  profileContext->provider_type = provider_type;

  return(notification);
}
