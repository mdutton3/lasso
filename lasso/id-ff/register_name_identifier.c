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

#include <lasso/environs/register_name_identifier.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_register_name_identifier_dump(LassoRegisterNameIdentifier *registration)
{
  LassoProfileContext *profileContext;
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(registration), NULL);

  return(dump);
}

gint
lasso_register_name_identifier_build_request_msg(LassoRegisterNameIdentifier *registration)
{
  LassoProfileContext *profileContext;
  LassoProvider       *provider;
  xmlChar             *protocolProfile;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(registration), -1);
  
  profileContext = LASSO_PROFILE_CONTEXT(registration);

  /* get the prototocol profile of the register_name_identifier */
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider);
  if(protocolProfile==NULL){
    debug(ERROR, "Register name identifier protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileRniSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileRniIdpSoap)){
    debug(DEBUG, "Building a register name identifier request soap message\n");
    profileContext->request_type = lassoHttpMethodSoap;
    profileContext->msg_url = lasso_provider_get_registerNameIdentifierServiceURL(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniIdpHttp)){
    debug(DEBUG, "building a register name identifier request http redirect message\n");
    profileContext->request_type = lassoHttpMethodRedirect;
    lasso_register_name_identifier_rename_attributes_for_query(LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(profileContext->request));
    profileContext->msg_url = lasso_node_export_to_query(profileContext->request,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

gint
lasso_register_name_identifier_build_response_msg(LassoRegisterNameIdentifier *registration)
{
  LassoProfileContext *profileContext;
  LassoProvider       *provider;
  xmlChar             *protocolProfile;
  
  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(registration), -1);

  profileContext = LASSO_PROFILE_CONTEXT(registration);

  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider);
  if(protocolProfile==NULL){
    debug(ERROR, "Register_Name_Identifier Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileRniSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileRniIdpSoap)){
    debug(DEBUG, "Building a register name identifier request soap message\n");
    profileContext->msg_url = lasso_provider_get_registerNameIdentifierServiceURL(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->response);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniIdpHttp)){
    debug(DEBUG, "building a register name identifier request HTTP redirect message\n");
    profileContext->response_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->response,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

gint
lasso_register_name_identifier_init_request(LassoRegisterNameIdentifier *registration,
					    gchar                       *remote_providerID)
{
  LassoProfileContext                 *profileContext;
  LassoNode                           *nameIdentifier_node;
  LassoIdentity                       *identity;
  LassoRegisterNameIdentifierRequest  *request;

  xmlChar *idpNameIdentifier, *idpNameQualifier, *idpFormat;
  xmlChar *spNameIdentifier,  *spNameQualifier,  *spFormat;
  xmlChar *oldNameIdentifier, *oldNameQualifier, *oldFormat;

  xmlChar *providerID;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(registration), -1);

  providerID = lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server));

  profileContext = LASSO_PROFILE_CONTEXT(registration);
  profileContext->remote_providerID = remote_providerID;

  /* TODO : implement the setting of the request */
  switch(profileContext->provider_type){
  case lassoProviderTypeSp:
    /* generate a new local name identifier */
    spNameIdentifier = lasso_build_unique_id(32);
    spNameQualifier  = providerID;
    spFormat = "federated";

    /* get the old name identifier */
    identity = lasso_user_get_identity(profileContext->user, remote_providerID);
    nameIdentifier_node = lasso_identity_get_local_nameIdentifier(identity);
    if(nameIdentifier_node){
      oldNameIdentifier = lasso_node_get_content(nameIdentifier_node);
      oldNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier");
      oldFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format");    
    }

    /* get the remote name identifier */
    identity = lasso_user_get_identity(profileContext->user, remote_providerID);
    nameIdentifier_node = lasso_identity_get_remote_nameIdentifier(identity);
    idpNameIdentifier = lasso_node_get_content(nameIdentifier_node);
    idpNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier");
    idpFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format");
    break;
  case lassoProviderTypeIdp:
    /* generate a new local name identifier */
    idpNameIdentifier = lasso_build_unique_id(32);
    idpNameQualifier  = providerID;
    idpFormat = "federated";

    /* get the old name identifier */
    identity = lasso_user_get_identity(profileContext->user, remote_providerID);
    nameIdentifier_node = lasso_identity_get_local_nameIdentifier(identity);
    oldNameIdentifier = lasso_node_get_content(nameIdentifier_node);
    oldNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier");
    oldFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format");    

    /* get the remote name identifier */
    identity = lasso_user_get_identity(profileContext->user, remote_providerID);
    nameIdentifier_node = lasso_identity_get_remote_nameIdentifier(identity);
    spNameIdentifier = lasso_node_get_content(nameIdentifier_node);
    spNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier");
    spFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format");
    break;
  default:
    debug(ERROR, "Unknown provider type (%d)\n", profileContext->provider_type);
  }

  lasso_register_name_identifier_request_new(providerID,
					     idpNameIdentifier,
					     idpNameQualifier,
					     idpFormat,
					     spNameIdentifier,
					     spNameQualifier,
					     spFormat,
					     oldNameIdentifier,
					     oldNameQualifier,
					     oldFormat);
    
  return(0);
}

gint
lasso_register_name_identifier_handle_request_msg(LassoRegisterNameIdentifier *registration,
						  gchar                       *request_msg,
						  lassoHttpMethods             request_method)
{
  LassoProfileContext *profileContext;
  LassoIdentity       *identity;
  LassoNode           *nameIdentifier, *assertion;
  LassoNode           *statusCode;
  LassoNodeClass      *statusCode_class;
  xmlChar             *remote_providerID;

  profileContext = LASSO_PROFILE_CONTEXT(registration);

  switch(request_method){
  case lassoHttpMethodSoap:
    debug(DEBUG, "Build a register name identifier request from soap message\n");
    profileContext->request = lasso_register_name_identifier_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    debug(DEBUG, "build a register name identifier request from query message\n");
    profileContext->request = lasso_register_name_identifier_request_new_from_query(request_msg);
    break;
  case lassoHttpMethodGet:
    debug(WARNING, "TODO, implement the get method\n");
    break;
  default:
    debug(ERROR, "Unknown request method\n");
    return(-1);
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  profileContext->remote_providerID = remote_providerID;

  /* set RegisterNameIdentifierResponse */
  profileContext->response = lasso_register_name_identifier_response_new(
								  lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
								  lassoSamlStatusCodeSuccess,
								  profileContext->request);

  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
  if(nameIdentifier==NULL){
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-2);
  }

  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);

  return(0);
}

gint
lasso_register_name_identifier_handle_response_msg(LassoRegisterNameIdentifier *registration,
						   gchar                       *response_msg,
						   lassoHttpMethods             response_method)
{
  LassoProfileContext *profileContext;
  xmlChar   *statusCodeValue;
  LassoNode *statusCode;

  profileContext = LASSO_PROFILE_CONTEXT(registration);

  /* parse RegisterNameIdentifierResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profileContext->response = lasso_register_name_identifier_response_new_from_soap(response_msg);
  case lassoHttpMethodRedirect:
    profileContext->response = lasso_register_name_identifier_response_new_from_query(response_msg);
  default:
    debug(ERROR, "Unkown response method (%d)\n", response_method);
  }
 
  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value");
  if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)){
    return(-1);
  }

  return(0);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_register_name_identifier_instance_init(LassoRegisterNameIdentifier *register_name_identifier)
{

}

static void
lasso_register_name_identifier_class_init(LassoRegisterNameIdentifierClass *klass)
{

}

GType lasso_register_name_identifier_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoRegisterNameIdentifierClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_register_name_identifier_class_init,
      NULL,
      NULL,
      sizeof(LassoRegisterNameIdentifier),
      0,
      (GInstanceInitFunc) lasso_register_name_identifier_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoRegisterNameIdentifier",
				       &this_info, 0);
  }
  return this_type;
}

LassoRegisterNameIdentifier *
lasso_register_name_identifier_new(LassoServer *server,
				   LassoUser   *user,
				   gint         provider_type)
{
  LassoRegisterNameIdentifier *registration;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(LASSO_IS_USER(user), NULL);

  /* set the register_name_identifier object */
  registration = g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER,
			      "server", server,
			      "user", user,
			      "provider_type", provider_type,
			      NULL);
  return(registration);
}
