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
    message(G_LOG_LEVEL_ERROR, "Federation not found\n");
    ret = -1;
    goto done;
  }

  /* get the name identifier */
  nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
  if(nameIdentifier == NULL) {
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
  }
  if (nameIdentifier != NULL) {
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
												 lassoProviderTypeSp,
												 NULL);
  if (nameIdentifierMappingProtocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier mapping protocol profile not found\n");
    ret = -1;
    goto done;
  }

  /* build the request */
  if (xmlStrEqual(nameIdentifierMappingProtocolProfile, lassoLibProtocolProfileNimSpSoap)) {
    profile->request = lasso_name_identifier_mapping_request_new(profile->server->providerID,
								 content,
								 nameQualifier,
								 format,
								 targetNameSpace,
								 lassoSignatureTypeWithX509,
								 lassoSignatureMethodRsaSha1);
  }
  else if (xmlStrEqual(nameIdentifierMappingProtocolProfile, lassoLibProtocolProfileNimSpHttp)) {
    profile->request = lasso_name_identifier_mapping_request_new(profile->server->providerID,
								 content,
								 nameQualifier,
								 format,
								 targetNameSpace,
								 lassoSignatureTypeNone,
								 0);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid federation termination notification protocol profile\n");
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
  g_return_val_if_fail(request_msg!=NULL, -1);

  profile = LASSO_PROFILE(mapping);

  switch(request_method){
  case lassoHttpMethodSoap:
    profile->request = lasso_name_identifier_mapping_request_new_from_export(request_msg, lassoNodeExportTypeSoap);
    if (LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
      message(G_LOG_LEVEL_CRITICAL, "Message is not a NameIdentifierMappingRequest\n");
      ret = -1;
      goto done;
    }
    break;
  case lassoHttpMethodRedirect:
    profile->request = lasso_name_identifier_mapping_request_new_from_export(request_msg, lassoNodeExportTypeQuery);
    if (LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
      ret = LASSO_PROFILE_ERROR_INVALID_QUERY;
      goto done;
    }
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Invalid request method\n");
    ret = -1;
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
  case lassoHttpMethodRedirect:
    profile->response = lasso_name_identifier_mapping_response_new_from_export(response_msg, lassoNodeExportTypeQuery);
  default:
    message(G_LOG_LEVEL_ERROR, "Invalid response method\n");
    ret = -1;
    goto done;
  }
 
  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", &err);
  if (err == NULL) {
    if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)) {
      ret = -1;
      goto done;
    }
  }
  else {
    message(G_LOG_LEVEL_ERROR, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  done:

  return 0;
}

gint
lasso_name_identifier_mapping_validate_request(LassoNameIdentifierMapping *mapping)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  gint             ret = 0;
  gint             remote_provider_type;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping) == TRUE, -1);

  profile = LASSO_PROFILE(mapping);

  /* verify the name identifier mapping request */
  if (LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Invalid NameIdentifierMappingRequest\n");
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

  /* get the remote provider type */
  if (profile->provider_type == lassoProviderTypeSp) {
    remote_provider_type = lassoProviderTypeIdp;
  }
  else if (profile->provider_type == lassoProviderTypeIdp) {
    remote_provider_type = lassoProviderTypeSp;
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "invalid provider type\n");
    ret = -1;
    goto done;
  }



  done:

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
lasso_name_identifier_mapping_new(LassoServer       *server)
{
  LassoNameIdentifierMapping *mapping;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the name_identifier_mapping object */
  mapping = g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING,
			 "server", lasso_server_copy(server),
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
