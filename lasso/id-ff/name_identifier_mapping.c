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

#include <lasso/xml/errors.h>

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

  /* verify the provider type is a service provider type */
  if (profile->provider_type != lassoProviderTypeSp) {
    message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden for an IDP\n");
    ret = -1;
    goto done;
  }

  /* get provider object */
  provider = lasso_server_get_provider_ref(profile->server,
					   profile->remote_providerID,
					   NULL);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider %s not found\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  /* get the prototocol profile of the name identifier mapping request */
  protocolProfile = lasso_provider_get_nameIdentifierMappingProtocolProfile(provider,
									    lassoProviderTypeIdp,
									    NULL);
  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier mapping protocol profile not found\n");
    ret = -1;
    goto done;
  }

  /* Build the name identifier mapping request message (SOAP or QUERY type) */
  if(xmlStrEqual(protocolProfile, lassoLibProtocolProfileNimSpHttp)) {
    profile->msg_url = lasso_provider_get_soapEndpoint(provider,
						       lassoProviderTypeIdp,
						       NULL);
    if (profile->msg_url == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Name identifier mapping url not found\n");
      ret = -1;
      goto done;
    }

    profile->msg_body = lasso_node_export_to_soap(profile->request);
    if (profile->msg_body == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Error while building name identifier mapping request SOAP message\n");
      ret = -1;
      goto done;
    }
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid protocol profile\n");
    ret = -1;
    goto done;
  }

  done:

  return ret;
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

  /* verify the provider type is a service provider type */
  if (profile->provider_type != lassoProviderTypeIdp) {
    message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden for an SP\n");
    ret = -1;
    goto done;
  }

  /* build name identifier mapping response msg */
  switch (profile->http_request_method) {
  case lassoHttpMethodSoap:
    profile->msg_url = NULL;
    profile->msg_body = lasso_node_export_to_soap(profile->response);
    break;
  case lassoHttpMethodRedirect:
    profile->msg_url = lasso_node_export_to_query(profile->response,
						  profile->server->signature_method,
						  profile->server->private_key);
    profile->msg_body = NULL;    
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid http request method\n");
    ret = -1;
    goto done;
  }

  done:

  return ret;
}

void
lasso_name_identifier_mapping_destroy(LassoNameIdentifierMapping *mapping)
{
  g_object_unref(G_OBJECT(mapping));
}

gint
lasso_name_identifier_mapping_init_request(LassoNameIdentifierMapping *mapping,
					   gchar                      *targetNameSpace,
					   gchar                      *remote_providerID)
{
  LassoProfile    *profile;
  LassoNode       *nameIdentifier;
  LassoProvider   *provider;
  LassoFederation *federation;
  xmlChar         *content, *nameQualifier, *format, *nameIdentifierMappingProtocolProfile;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(targetNameSpace != NULL, -1);

  profile = LASSO_PROFILE(mapping);

  /* verify the provider type is a service provider type */
  if (profile->provider_type != lassoProviderTypeSp) {
    message(G_LOG_LEVEL_CRITICAL, "Init request method is forbidden for an IDP\n");
    ret = -1;
    goto done;
  }

  /* verify if the identity exists */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }

  /* set the remote provider id */
  if (remote_providerID == NULL) {
    profile->remote_providerID = lasso_identity_get_first_providerID(profile->identity);
  }
  else {
    profile->remote_providerID = g_strdup(remote_providerID);
  }
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Remote provider id not found\n");
    ret = -1;
    goto done;
  }
  
  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    ret = -1;
    goto done;
  }
  /* get the name identifier */
  nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
  if(nameIdentifier == NULL) {
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
  }
  if (nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found\n");
    ret = -1;
    goto done;
  }
  lasso_federation_destroy(federation);

  /* get content and attributes of name identifier */
  content = lasso_node_get_content(nameIdentifier, NULL);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  if (content == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Content of name identifier not found\n");
    ret = -1;
    goto done;
  }

  /* get protocol profile */
  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, NULL);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider %s not found\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  nameIdentifierMappingProtocolProfile = lasso_provider_get_nameIdentifierMappingProtocolProfile(provider,
												 lassoProviderTypeIdp,
												 NULL);
  if (nameIdentifierMappingProtocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier mapping protocol profile not found\n");
    ret = -1;
    goto done;
  }

  /* build the request */
  if (xmlStrEqual(nameIdentifierMappingProtocolProfile, lassoLibProtocolProfileNimSpHttp)) {
    profile->request = lasso_name_identifier_mapping_request_new(profile->server->providerID,
								 content,
								 nameQualifier,
								 format,
								 targetNameSpace,
								 lassoSignatureTypeWithX509,
								 lassoSignatureMethodRsaSha1);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid name identifier mapping protocol profile\n");
    ret = -1;
    goto done;
  }

  done:

  return ret;
}

gint
lasso_name_identifier_mapping_process_request_msg(LassoNameIdentifierMapping *mapping,
						  gchar                      *request_msg,
						  lassoHttpMethod             request_method)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  LassoNode       *nameIdentifier;
  LassoNode       *statusCode;
  LassoNodeClass  *statusCode_class;
  xmlChar         *remote_providerID;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(request_msg != NULL, -1);

  profile = LASSO_PROFILE(mapping);

  switch(request_method){
  case lassoHttpMethodRedirect:
    message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_QUERY));
    ret = LASSO_PROFILE_ERROR_INVALID_QUERY;
    goto done;
    break;
  case lassoHttpMethodSoap:
    profile->request = lasso_name_identifier_mapping_request_new_from_export(request_msg, lassoNodeExportTypeSoap);
    if (LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
      message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG));
      ret = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
      goto done;
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD));
    ret = LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
    goto done;
  }

  /* set the http request method */
  profile->http_request_method = request_method;

  /* NameIdentifier */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier", NULL, NULL);

  done:

  return ret;
}

gint
lasso_name_identifier_mapping_process_response_msg(LassoNameIdentifierMapping *mapping,
						   gchar                      *response_msg,
						   lassoHttpMethod             response_method)
{
  LassoProfile *profile;
  xmlChar      *statusCodeValue;
  LassoNode    *statusCode;
  GError       *err = NULL;
  gint          ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(response_msg != NULL, -1);

  profile = LASSO_PROFILE(mapping);

  switch(response_method){
  case lassoHttpMethodSoap:
    profile->response = lasso_name_identifier_mapping_response_new_from_export(response_msg, lassoNodeExportTypeSoap);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid response method\n");
    ret = -1;
    goto done;
  }
  if (LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building NameIdentifierMappingResponse message\n");
    ret = -1;
    goto done;
  }

  /* Verify the status code value */
  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  if (statusCode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Status code not found\n");
    ret = -1;
    goto done;
  }
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", NULL);
  if (statusCodeValue == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Status code value not found\n");
    ret = -1;
    goto done;
  }
  if (xmlStrEqual(statusCodeValue, lassoLibStatusCodeFederationDoesNotExist)) {
    message(G_LOG_LEVEL_CRITICAL, "Status code : Federation does not exists\n");
    ret = -1;
    goto done;
  }
  else if (xmlStrEqual(statusCodeValue, lassoLibStatusCodeUnknownPrincipal)) {
    message(G_LOG_LEVEL_CRITICAL, "Status code : Unknown Principal\n");
    ret = -1;
    goto done;
  }

  /* Set the target name identifier */
  mapping->targetNameIdentifier = lasso_node_get_child_content(profile->response, "NameIdentifier", NULL, NULL);

  done:

  return ret;
}

gint
lasso_name_identifier_mapping_validate_request(LassoNameIdentifierMapping *mapping)
{
  LassoProfile    *profile = NULL;
  LassoFederation *federation = NULL;
  LassoNode       *nameIdentifier = NULL, *targetNameIdentifier = NULL;
  gchar           *remote_providerID = NULL, *targetNameSpace = NULL;
  gint             ret = 0;
  gint             remote_provider_type;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping) == TRUE, -1);

  profile = LASSO_PROFILE(mapping);

  /* verify the provider type is a service provider type */
  if (profile->provider_type != lassoProviderTypeIdp) {
    message(G_LOG_LEVEL_CRITICAL, "Build request msg method is forbidden for an SP\n");
    ret = -1;
    goto done;
  }

  /* verify request attribute of mapping is a name identifier mapping request */
  if (LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid NameIdentifierMappingRequest\n");
    ret = -1;
    goto done;
  }

  /* set the name identifier mapping response object */
  switch (profile->http_request_method) {
    case lassoHttpMethodSoap:
      profile->response = lasso_name_identifier_mapping_response_new(profile->server->providerID,
								     (gchar *)lassoSamlStatusCodeSuccess,
								     profile->request,
								     lassoSignatureTypeWithX509,
								     lassoSignatureMethodRsaSha1);
      break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP request method\n");
    ret = -1;
    goto done;
  }
  if (LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building NameIdentifierMappingResponse\n");
    ret = -1;
    goto done;
  }

  /* set the remote provider id from the request */
  profile->remote_providerID = lasso_node_get_child_content(profile->request,
							    "ProviderID",
							    NULL,
							    NULL);
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Remote provider id not found\n");
    ret = -1;
    goto done;
  }

  /* Verify identity attribute of mapping object */
  if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }

  /* verify federation of the SP request */
  federation = lasso_identity_get_federation_ref(profile->identity, profile->remote_providerID);
  if (LASSO_IS_FEDERATION(federation) == FALSE) {
    lasso_name_identifier_mapping_response_set_status_code_value(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response),
								 lassoLibStatusCodeUnknownPrincipal);
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    ret = -1;
    goto done;
  }
  nameIdentifier = lasso_federation_get_remote_nameIdentifier(federation);
  if (nameIdentifier == NULL) {
    nameIdentifier = lasso_federation_get_local_nameIdentifier(federation);
  }
  if (nameIdentifier == NULL) {
    lasso_name_identifier_mapping_response_set_status_code_value(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response),
								 lassoLibStatusCodeUnknownPrincipal);
    message(G_LOG_LEVEL_CRITICAL, "Name identifier of federation not found\n");
    ret = -1;
    goto done;
  }
  lasso_node_destroy(nameIdentifier);

  /* get the federation of the target name space and his name identifier */
  targetNameSpace = lasso_node_get_child_content(profile->request, "TargetNameSpace", NULL, NULL);
  if (targetNameSpace == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Target name space not found\n");
    ret = -1;
    goto done;
  }
  federation = lasso_identity_get_federation_ref(profile->identity, targetNameSpace);
  if (LASSO_IS_FEDERATION(federation) == FALSE) {
    lasso_name_identifier_mapping_response_set_status_code_value(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response),
								 lassoLibStatusCodeFederationDoesNotExist);
    message(G_LOG_LEVEL_CRITICAL, "Target name space federation not found\n");
    ret = -1;
    goto done;    
  }
  targetNameIdentifier = lasso_federation_get_remote_nameIdentifier(federation);
  if (targetNameIdentifier == NULL) {
    targetNameIdentifier = lasso_federation_get_local_nameIdentifier(federation);
  }
  if (targetNameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier for target name space federation not found\n");
    lasso_name_identifier_mapping_response_set_status_code_value(LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response),
								 lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }
  lasso_lib_name_identifier_mapping_response_set_nameIdentifier(LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response),
								LASSO_SAML_NAME_IDENTIFIER(targetNameIdentifier));

  done:
  if (nameIdentifier != NULL) {
    lasso_node_destroy(nameIdentifier);
  }
  if (targetNameIdentifier != NULL) {
    lasso_node_destroy(targetNameIdentifier);
  }

  return ret;
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
lasso_name_identifier_mapping_new(LassoServer      *server,
				  lassoProviderType provider_type)
{
  LassoNameIdentifierMapping *mapping;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail((provider_type == lassoProviderTypeSp) || (provider_type == lassoProviderTypeIdp), NULL);

  /* set the name_identifier_mapping object */
  mapping = g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING,
			 "server", lasso_server_copy(server),
			 "provider_type", provider_type,
			 NULL);
  return mapping;
}

LassoNameIdentifierMapping *
lasso_name_identifier_mapping_new_from_dump(LassoServer *server,
					    gchar       *dump)
{
  LassoNameIdentifierMapping *mapping;
  LassoNode                  *node_dump;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(dump != NULL, NULL);
  
  mapping = g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING,
			 "server", lasso_server_copy(server),
			 NULL);

  node_dump = lasso_node_new_from_dump(dump);

  return mapping;
}
