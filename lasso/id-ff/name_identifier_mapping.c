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

#include <lasso/environs/name_identifier_mapping.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_name_identifier_mapping_dump(LassoNameIdentifierMapping *mapping)
{
  LassoProfileContext *profileContext;
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), NULL);

  return(dump);
}

gint
lasso_name_identifier_mapping_build_request_msg(LassoNameIdentifierMapping *mapping)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  
  profileContext = LASSO_PROFILE_CONTEXT(mapping);

  /* get the prototocol profile of the name_identifier_mapping */
  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_nameIdentifierMappingProtocolProfile(provider);
  if(protocolProfile==NULL){
    debug(ERROR, "Single Name_Identifier_Mapping Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug(DEBUG, "building a soap request message\n");
    profileContext->request_type = lassoHttpMethodSoap;
    profileContext->msg_url = lasso_provider_get_nameIdentifierMappingServiceURL(provider);
    profileContext->msg_body = lasso_node_export_to_soap(profileContext->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp)||xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)){
    debug(DEBUG, "building a http get request message\n");
    profileContext->request_type = lassoHttpMethodRedirect;
    profileContext->msg_url = lasso_node_export_to_query(profileContext->request,
							 profileContext->server->signature_method,
							 profileContext->server->private_key);
    profileContext->msg_body = NULL;
  }

  return(0);
}

gint
lasso_name_identifier_mapping_build_response_msg(LassoNameIdentifierMapping *mapping)
{
  LassoProfileContext *profileContext;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);

  profileContext = LASSO_PROFILE_CONTEXT(mapping);

  provider = lasso_server_get_provider(profileContext->server, profileContext->remote_providerID);
  if(provider==NULL){
    debug(ERROR, "Provider %s not found\n", profileContext->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_nameIdentifierMappingProtocolProfile(provider);
  if(protocolProfile==NULL){
    debug(ERROR, "Single Name_Identifier_Mapping Protocol profile not found\n");
    return(-3);
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)){
    debug(DEBUG, "building a soap response message\n");
    profileContext->msg_url = lasso_provider_get_nameIdentifierMappingServiceURL(provider);
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

gint
lasso_name_identifier_mapping_init_request(LassoNameIdentifierMapping *mapping,
			  gchar       *remote_providerID)
{
  LassoProfileContext *profileContext;
  LassoNode           *nameIdentifier;
  LassoIdentity       *identity;
  LassoNameIdentifierMappingRequest  *request;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(remote_providerID!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(mapping);

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
    debug(ERROR, "Name identifier not found\n");
    return(-5);
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier");
  format = lasso_node_get_attr_value(nameIdentifier, "Format");
  profileContext->request = lasso_name_identifier_mapping_request_new(
						     lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
						     content,
						     nameQualifier,
						     format);

  g_return_val_if_fail(profileContext->request!=NULL, -6);

  return(0);
}

gint
lasso_name_identifier_mapping_process_request_msg(LassoNameIdentifierMapping *mapping,
						  gchar                      *request_msg,
						  lassoHttpMethods            request_method)
{
  LassoProfileContext *profileContext;
  LassoIdentity *identity;
  LassoNode *nameIdentifier, *assertion;
  LassoNode *statusCode;
  LassoNodeClass *statusCode_class;
  xmlChar *remote_providerID;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(request_msg!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(mapping);

  switch(request_method){
  case lassoHttpMethodSoap:
    debug(DEBUG, "build a name_identifier_mapping request from soap msg\n");
    profileContext->request = lasso_name_identifier_mapping_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    debug(DEBUG, "build a name_identifier_mapping request from query msg\n");
    profileContext->request = lasso_name_identifier_mapping_request_new_from_query(request_msg);
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

  /* set Name_Identifier_MappingResponse */
  profileContext->response = lasso_name_identifier_mapping_response_new(
                                                       lasso_provider_get_providerID(LASSO_PROVIDER(profileContext->server)),
						       lassoSamlStatusCodeSuccess,
						       profileContext->request);

  g_return_val_if_fail(profileContext->response!=NULL, -4);

  statusCode = lasso_node_get_child(profileContext->response, "StatusCode", NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profileContext->request, "NameIdentifier", NULL);
  if(nameIdentifier==NULL){
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-5);
  }

  remote_providerID = lasso_node_get_child_content(profileContext->request, "ProviderID", NULL);

  /* Verify federation */
  identity = lasso_user_get_identity(profileContext->user, remote_providerID);
  if(identity==NULL){
    debug(WARNING, "No identity for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-6);
  }

  if(lasso_identity_verify_nameIdentifier(identity, nameIdentifier)==FALSE){
    debug(WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return(-7);
  }

  return(0);
}

gint
lasso_name_identifier_mapping_process_response_msg(LassoNameIdentifierMapping *mapping,
						   gchar                      *response_msg,
						   lassoHttpMethods            response_method)
{
  LassoProfileContext *profileContext;
  xmlChar   *statusCodeValue;
  LassoNode *statusCode;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(response_msg!=NULL, -2);

  profileContext = LASSO_PROFILE_CONTEXT(mapping);

  /* parse NameIdentifierMappingResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profileContext->response = lasso_name_identifier_mapping_response_new_from_soap(response_msg);
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
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_name_identifier_mapping_instance_init(LassoNameIdentifierMapping *name_identifier_mapping)
{
}

static void
lasso_name_identifier_mapping_class_init(LassoNameIdentifierMappingClass *klass)
{
}

GType lasso_name_identifier_mapping_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoNameIdentifierMappingClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_name_identifier_mapping_class_init,
      NULL,
      NULL,
      sizeof(LassoNameIdentifierMapping),
      0,
      (GInstanceInitFunc) lasso_name_identifier_mapping_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoNameIdentifierMapping",
				       &this_info, 0);
  }
  return this_type;
}

LassoNameIdentifierMapping *
lasso_name_identifier_mapping_new(LassoServer        *server,
				  LassoUser          *user,
				  lassoProviderTypes  provider_type)
{
  LassoNameIdentifierMapping *mapping;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(LASSO_IS_USER(user), NULL);

  /* set the name_identifier_mapping object */
  mapping = g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING,
			"server", server,
			"user", user,
			"provider_type", provider_type,
			NULL);
  return(mapping);
}
