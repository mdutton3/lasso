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
  gchar *dump = NULL;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), NULL);

  return dump;
}

gint
lasso_name_identifier_mapping_build_request_msg(LassoNameIdentifierMapping *mapping)
{
  LassoProfile *profile;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  GError *err = NULL;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  
  profile = LASSO_PROFILE(mapping);

  /* get the prototocol profile of the name_identifier_mapping */
  provider = lasso_server_get_provider_ref(profile->server,
					   profile->remote_providerID,
					   NULL);
  if(provider == NULL) {
    message(G_LOG_LEVEL_ERROR, "Provider %s not found\n", profile->remote_providerID);
    return -2;
  }

  protocolProfile = lasso_provider_get_nameIdentifierMappingProtocolProfile(provider,
									    lassoProviderTypeIdp,
									    &err);
  if(err != NULL){
    message(G_LOG_LEVEL_ERROR, err->message);
    ret = err->code;
    g_error_free(err);
    return ret;
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
     xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    debug("building a soap request message\n");
    profile->request_type = lassoHttpMethodSoap;
    /* profile->msg_url = lasso_provider_get_nameIdentifierMappingServiceURL(provider, NULL); */
    profile->msg_body = lasso_node_export_to_soap(profile->request);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	  xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    debug("building a http get request message\n");
    profile->request_type = lassoHttpMethodRedirect;
    profile->msg_url = lasso_node_export_to_query(profile->request,
						  profile->server->signature_method,
						  profile->server->private_key);
    profile->msg_body = NULL;
  }

  return 0;
}

gint
lasso_name_identifier_mapping_build_response_msg(LassoNameIdentifierMapping *mapping)
{
  LassoProfile *profile;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  GError *err = NULL;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);

  profile = LASSO_PROFILE(mapping);

  provider = lasso_server_get_provider_ref(profile->server,
					   profile->remote_providerID,
					   NULL);
  if(provider == NULL) {
    message(G_LOG_LEVEL_ERROR, "Provider %s not found\n", profile->remote_providerID);
    return -2;
  }

  protocolProfile = lasso_provider_get_nameIdentifierMappingProtocolProfile(provider,
									    lassoProviderTypeSp,
									    &err);
  if(err != NULL) {
    message(G_LOG_LEVEL_ERROR, err->message);
    ret = err->code;
    g_error_free(err);
    return ret;
  }

  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
     xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    debug("building a soap response message\n");
    /* profile->msg_url = lasso_provider_get_nameIdentifierMappingServiceURL(provider, NULL); */
    profile->msg_body = lasso_node_export_to_soap(profile->response);
  }
  else if(xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	  xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    debug("building a http get response message\n");
    profile->response_type = lassoHttpMethodRedirect;
    profile->msg_url = lasso_node_export_to_query(profile->response,
						  profile->server->signature_method,
						  profile->server->private_key);
    profile->msg_body = NULL;
  }

  return 0;
}

gint
lasso_name_identifier_mapping_init_request(LassoNameIdentifierMapping *mapping,
					   gchar                      *remote_providerID)
{
  LassoProfile    *profile;
  LassoNode       *nameIdentifier;
  LassoFederation *federation;

  xmlChar *content, *nameQualifier, *format;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(remote_providerID != NULL, -2);

  profile = LASSO_PROFILE(mapping);

  profile->remote_providerID = remote_providerID;

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_ERROR, "error, federation not found\n");
    return -3;
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!)*/
  switch(profile->provider_type) {
  case lassoProviderTypeSp:
    debug("service provider\n");
    nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
    if(!nameIdentifier)
      nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
    break;
  case lassoProviderTypeIdp:
    debug("federation provider\n");
    /* get the next assertion (next authenticated service provider) */
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
    if(nameIdentifier == NULL) {
      nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
    }
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown provider type\n");
    return -4;
  }
  lasso_federation_destroy(federation);

  if(nameIdentifier == NULL) {
    message(G_LOG_LEVEL_ERROR, "Name identifier not found\n");
    return -5;
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier, NULL);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profile->request = lasso_name_identifier_mapping_request_new(profile->server->providerID,
							       content,
							       nameQualifier,
							       format);

  g_return_val_if_fail(profile->request != NULL, -6);

  return 0;
}

gint
lasso_name_identifier_mapping_process_request_msg(LassoNameIdentifierMapping *mapping,
						  gchar                      *request_msg,
						  lassoHttpMethod             request_method)
{
  LassoProfile *profile;
  LassoFederation *federation;
  LassoNode *nameIdentifier;
  LassoNode *statusCode;
  LassoNodeClass *statusCode_class;
  xmlChar *remote_providerID;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(request_msg!=NULL, -2);

  profile = LASSO_PROFILE(mapping);

  switch(request_method){
  case lassoHttpMethodSoap:
    debug("build a name_identifier_mapping request from soap msg\n");
    profile->request = lasso_name_identifier_mapping_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    debug("build a name_identifier_mapping request from query msg\n");
    profile->request = lasso_name_identifier_mapping_request_new_from_query(request_msg);
    break;
  case lassoHttpMethodGet:
    message(G_LOG_LEVEL_WARNING, "TODO, implement the get method\n");
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown request method\n");
    return -3;
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);
  profile->remote_providerID = remote_providerID;

  /* set Name_Identifier_MappingResponse */
  profile->response = lasso_name_identifier_mapping_response_new(profile->server->providerID,
								 lassoSamlStatusCodeSuccess,
								 profile->request);

  g_return_val_if_fail(profile->response!=NULL, -4);

  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profile->request, "NameIdentifier", NULL, NULL);
  if(nameIdentifier == NULL) {
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return -5;
  }

  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);

  /* Verify federation */
  federation = lasso_identity_get_federation(profile->identity, remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_WARNING, "No federation for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return -6;
  }

  if(lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE){
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    return -7;
  }
  lasso_federation_destroy(federation);

  return 0;
}

gint
lasso_name_identifier_mapping_process_response_msg(LassoNameIdentifierMapping *mapping,
						   gchar                      *response_msg,
						   lassoHttpMethod             response_method)
{
  LassoProfile *profile;
  xmlChar   *statusCodeValue;
  LassoNode *statusCode;
  GError *err = NULL;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(response_msg != NULL, -2);

  profile = LASSO_PROFILE(mapping);

  /* parse NameIdentifierMappingResponse */
  switch(response_method){
  case lassoHttpMethodSoap:
    profile->response = lasso_name_identifier_mapping_response_new_from_soap(response_msg);
  default:
    message(G_LOG_LEVEL_ERROR, "Unknown response method\n");
    return -3;
  }
 
  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", &err);
  if (err == NULL) {
    if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)) {
      return -4;
    }
  }
  else {
    message(G_LOG_LEVEL_ERROR, err->message);
    ret = err->code;
    g_error_free(err);
    return ret;
  }
  return 0;
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
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoNameIdentifierMapping",
				       &this_info, 0);
  }
  return this_type;
}

LassoNameIdentifierMapping *
lasso_name_identifier_mapping_new(LassoServer       *server,
				  LassoIdentity     *identity,
				  lassoProviderType  provider_type)
{
  LassoNameIdentifierMapping *mapping;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);

  /* set the name_identifier_mapping object */
  mapping = g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING,
			 "server", lasso_server_copy(server),
			 "identity", lasso_identity_copy(identity),
			 "provider_type", provider_type,
			 NULL);
  return mapping;
}
