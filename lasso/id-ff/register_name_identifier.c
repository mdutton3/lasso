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

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_register_name_identifier_dump(LassoRegisterNameIdentifier *register_name_identifier)
{
  LassoProfileContext *profileContext;
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), NULL);

  return(dump);
}

gint
lasso_register_name_identifier_build_request_msg(LassoRegisterNameIdentifier *register_name_identifier)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile, *registerNameIdentifierServiceURL;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  
  profileContext = LASSO_PROFILE_CONTEXT(register_name_identifier);

  /* get the prototocol profile of the register_name_identifier */
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  registerNameIdentifierServiceURL = lasso_provider_get_registerNameIdentifierServiceURL(provider);
  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider);

  if(protocolProfile==NULL){
    debug(ERROR, "Register_Name_Identifier Protocol profile not found\n");
    return(-3);
  }

  if(registerNameIdentifierServiceURL==NULL){
    debug(ERROR, "Register_Name_Identifier Service URL not found\n");
    return(-4);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug(DEBUG, "Building a soap request message\n");
    profileContext->request_type = lassoHttpMethodSoap;

    /* sign the request message */
    lasso_samlp_request_abstract_set_signature(LASSO_SAMLP_REQUEST_ABSTRACT(profileContext->request),
					       profileContext->server->signature_method,
					       profileContext->server->private_key,
					       profileContext->server->certificate);
    
    profileContext->msg_url  = registerNameIdentifierServiceURL;
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    debug(DEBUG, "Building a http get request message\n");
    profileContext->request_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->request,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

gint
lasso_register_name_identifier_build_response_msg(LassoRegisterNameIdentifier *register_name_identifier)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);

  profileContext = LASSO_PROFILE_CONTEXT(register_name_identifier);

  printf("get provider id %s\n",  profileContext->remote_providerID);
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider not found (ProviderID = %s)\n", profileContext->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider);
  if(protocolProfile==NULL){
    debug(ERROR, "Register_Name_Identifier Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug(DEBUG, "building a soap response message\n");
    profileContext->msg_url = lasso_provider_get_registerNameIdentifierServiceURL(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->response);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    debug(DEBUG, "building a http get response message\n");
    profileContext->response_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->response,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

void
lasso_register_name_identifier_destroy(LassoRegisterNameIdentifier *register_name_identifier)
{
  g_object_unref(G_OBJECT(register_name_identifier));
}

gint
lasso_register_name_identifier_init_request(LassoRegisterNameIdentifier *register_name_identifier,
					    gchar                       *remote_providerID)
{
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;
  LassoRegisterNameIdentifierRequest  *request;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  g_return_val_if_fail(remote_providerID!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(register_name_identifier);

  profileContext->remote_providerID = remote_providerID;

  /* get identity */
  identity = lasso_user_get_identity(profileContext->user, profileContext->remote_providerID);
  if(identity==NULL){
    debug(ERROR, "error, identity not found\n");
    return(-3);
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profileContext->provider_type){
  case lassoProviderTypeSp:
    printf("service provider\n");
    nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    break;
  case lassoProviderTypeIdp:
    printf("identity provider\n");
    /* get the next assertion ( next authenticated service provider ) */
    nameIdentifier = LASSO_NODE(lasso_identity_get_remote_nameIdentifier(identity));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_identity_get_local_nameIdentifier(identity));
    break;
  default:
    debug(ERROR, "Unknown provider type\n");
    return(-4);
  }
  
  if(!nameIdentifier){
    debug(ERROR, "error, name identifier not found\n");
    return(-5);
  }
  debug(DEBUG, "name identifier : %s\n", lasso_node_export(nameIdentifier));

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier");
  format = lasso_node_get_attr_value(nameIdentifier, "Format");
  profileContext->request = lasso_register_name_identifier_request_new(
								 lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
								 content,
								 nameQualifier,
								 format,
								 "",
								 "",
								 "",
								 "",
								 "",
								 "");

  if(profileContext->request==NULL){
    debug(ERROR, "Error while creating the request\n");
    return(-6);
  }

  return(0);
}

gint
lasso_register_name_identifier_process_request_msg(LassoRegisterNameIdentifier *register_name_identifier,
						   gchar                       *request_msg,
						   lassoHttpMethods             request_method)
{
  LassoProfileContext *profileContext;
  LassoIdentity *identity;
  LassoNode *nameIdentifier, *assertion;
  LassoNode *statusCode;
  LassoNodeClass *statusCode_class;
  xmlChar *remote_providerID;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  g_return_val_if_fail(request_msg!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(register_name_identifier);

  switch(request_method){
  case lassoHttpMethodSoap:
    debug(DEBUG, "build a register_name_identifier request from soap msg\n");
    profileContext->request = lasso_register_name_identifier_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    debug(DEBUG, "build a register_name_identifier request from query msg\n");
    profileContext->request = lasso_register_name_identifier_request_new_from_query(request_msg);
    break;
  case lassoHttpMethodGet:
    debug(WARNING, "TODO, implement the get method\n");
    break;
  default:
    debug(ERROR, "Unknown request method\n");
    return(-3);
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  profileContext->remote_providerID = remote_providerID;

  /* set RegisterNameIdentifierResponse */
  profileContext->response = lasso_register_name_identifier_response_new(
								  lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
								  lassoSamlStatusCodeSuccess,
								  profileContext->request);

  if(profileContext->response==NULL){
    debug(ERROR, "Error while building response\n");
    return(-4);
  }

  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
  if(nameIdentifier==NULL){
    debug(ERROR, "No name identifier found in register_name_identifier request\n");
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-5);
  }

  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);
  if(remote_providerID==NULL){
    debug(ERROR, "No provider id found in register_name_identifier request\n");
    return(-6);
  }

  /* Verify federation */
  identity = lasso_user_get_identity(profileContext->user, remote_providerID);
  if(identity==NULL){
    debug(WARNING, "No identity for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-7);
  }

  if(lasso_identity_verify_nameIdentifier(identity, nameIdentifier)==FALSE){
    debug(WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-8);
  }

  /* verify authentication (if ok, delete assertion) */
  assertion = lasso_user_get_assertion(profileContext->user, remote_providerID);
  if(assertion==NULL){
    debug(WARNING, "%s has no assertion\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    return(-9);
  }

  return(0);
}

gint
lasso_register_name_identifier_process_response_msg(LassoRegisterNameIdentifier *register_name_identifier,
						    gchar                       *response_msg,
						    lassoHttpMethods             response_method)
{
  LassoProfileContext *profileContext;
  xmlChar   *statusCodeValue;
  LassoNode *statusCode;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  g_return_val_if_fail(response_msg!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(register_name_identifier);

  /* parse RegisterNameIdentifierResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profileContext->response = lasso_register_name_identifier_response_new_from_soap(response_msg);
    break;
  case lassoHttpMethodRedirect:
    profileContext->response = lasso_register_name_identifier_response_new_from_query(response_msg);
    break;
  default:
    debug(ERROR, "Unknown response method\n");
    return(-3);
  }
 
  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value");
  if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)){
    return(-4);
  }

  return(0);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_register_name_identifier_finalize(LassoRegisterNameIdentifier *register_name_identifier)
{  
  debug(INFO, "Register Name Identifier object 0x%x finalized ...\n", register_name_identifier);

  parent_class->finalize(G_OBJECT(register_name_identifier));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_register_name_identifier_instance_init(LassoRegisterNameIdentifier *register_name_identifier)
{
}

static void
lasso_register_name_identifier_class_init(LassoRegisterNameIdentifierClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->finalize = (void *)lasso_register_name_identifier_finalize;
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
lasso_register_name_identifier_new(LassoServer        *server,
				   LassoUser          *user,
				   lassoProviderTypes  provider_type)
{
  LassoRegisterNameIdentifier *register_name_identifier;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(LASSO_IS_USER(user), NULL);

  /* set the register_name_identifier object */
  register_name_identifier = g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER,
					  "server", server,
					  "user", user,
					  "provider_type", provider_type,
					  NULL);

  return(register_name_identifier);
}































/* gint */
/* lasso_register_name_identifier_init_request(LassoRegisterNameIdentifier *registration, */
/* 					    gchar                       *remote_providerID) */
/* { */

/*   /\* TODO : implement the setting of the request *\/ */
/*   switch(profileContext->provider_type){ */
/*   case lassoProviderTypeSp: */
/*     /\* generate a new local name identifier *\/ */
/*     spNameIdentifier = lasso_build_unique_id(32); */
/*     spNameQualifier  = providerID; */
/*     spFormat = "federated"; */

/*     debug(DEBUG, "new name identifier : %s, name qualifier : %s, format : %s\n", spNameIdentifier, spNameQualifier, spFormat); */

/*     /\* get the old name identifier *\/ */
/*     identity = lasso_user_get_identity(profileContext->user, remote_providerID); */
/*     if(identity==NULL){ */
/*       debug(ERROR, "Identity not found\n"); */
/*       return(-3); */
/*     } */
/*     nameIdentifier_node = lasso_identity_get_local_nameIdentifier(identity); */
/*     if(nameIdentifier_node){ */
/*       oldNameIdentifier = lasso_node_get_content(nameIdentifier_node); */
/*       oldNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier"); */
/*       oldFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format");     */
/*     } */

/*     /\* get the remote name identifier *\/ */
/*     nameIdentifier_node = lasso_identity_get_remote_nameIdentifier(identity); */
/*     idpNameIdentifier = lasso_node_get_content(nameIdentifier_node); */
/*     idpNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier"); */
/*     idpFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format"); */
/*     break; */

/*   case lassoProviderTypeIdp: */
/*     /\* generate a new local name identifier *\/ */
/*     idpNameIdentifier = lasso_build_unique_id(32); */
/*     idpNameQualifier  = providerID; */
/*     idpFormat = "federated"; */

/*     /\* get the old name identifier *\/ */
/*     identity = lasso_user_get_identity(profileContext->user, remote_providerID); */
/*     if(identity==NULL){ */
/*       debug(ERROR, "Identity not found\n"); */
/*       return(-4); */
/*     } */
/*     nameIdentifier_node = lasso_identity_get_local_nameIdentifier(identity); */
/*     oldNameIdentifier = lasso_node_get_content(nameIdentifier_node); */
/*     oldNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier"); */
/*     oldFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format");     */

/*     /\* get the remote name identifier *\/ */
/*     nameIdentifier_node = lasso_identity_get_remote_nameIdentifier(identity); */
/*     spNameIdentifier = lasso_node_get_content(nameIdentifier_node); */
/*     spNameQualifier = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier"); */
/*     spFormat = lasso_node_get_attr_value(nameIdentifier_node, "Format"); */
/*     break; */

/*   default: */
/*     debug(ERROR, "Unknown provider type (%d)\n", profileContext->provider_type); */
/*     return(-5); */
/*   } */

/*   return(0); */
/* } */
