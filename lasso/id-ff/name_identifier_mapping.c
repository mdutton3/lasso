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
					   gchar                      *remote_providerID,
					   gchar                      *targetNameSpace)
{
  LassoProfile    *profile;
  LassoNode       *nameIdentifier;
  LassoFederation *federation;
  xmlChar         *content, *nameQualifier, *format;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);
  g_return_val_if_fail(remote_providerID != NULL, -1);

  profile = LASSO_PROFILE(mapping);

  /* verify if the identity exists */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }

  /* get the remote provider id */
  /* If remote_providerID is NULL, then get the first remote provider id in session */
  if (remote_providerID == NULL) {
    profile->remote_providerID = lasso_identity_get_first_providerID(profile->identity);
  }
  else {
    profile->remote_providerID = g_strdup(remote_providerID);
  }
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id for init request\n");
    ret = -1;
    goto done;
  }

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_ERROR, "error, federation not found\n");
    ret = -1;
    goto done;
  }

  /* get the name identifier */
  nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
  if(nameIdentifier == NULL) {
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
  }

  if(nameIdentifier == NULL) {
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
  }
  if (nameIdentifier != NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found\n");
    ret = -1;
    goto done;
  }

  lasso_federation_destroy(federation);

  /* build the request */
  content = lasso_node_get_content(nameIdentifier, NULL);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profile->request = lasso_name_identifier_mapping_request_new(profile->server->providerID,
							       content,
							       nameQualifier,
							       format,
							       targetNameSpace);

  if (LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(profile->request) == FALSE) {
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
    profile->request = lasso_name_identifier_mapping_request_new_from_soap(request_msg);
    break;
  case lassoHttpMethodRedirect:
    profile->request = lasso_name_identifier_mapping_request_new_from_query(request_msg);
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Invalid request method\n");
    ret = -1;
    goto done;
  }

  /* set the remote provider id from the request */
  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);
  profile->remote_providerID = remote_providerID;


  profile->response = lasso_name_identifier_mapping_response_new(profile->server->providerID,
								 lassoSamlStatusCodeSuccess,
								 profile->request);

  g_return_val_if_fail(profile->response!=NULL, -1);

  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profile->request, "NameIdentifier", NULL, NULL);
  if(nameIdentifier == NULL) {
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID",
						   NULL, NULL);

  /* Verify federation */
  federation = lasso_identity_get_federation(profile->identity, remote_providerID);
  if(federation == NULL) {
    message(G_LOG_LEVEL_WARNING, "No federation for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  if(lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE){
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }
  lasso_federation_destroy(federation);

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
    profile->response = lasso_name_identifier_mapping_response_new_from_soap(response_msg);
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
  LassoNode       *nameIdentifier, *assertion;
  LassoNode       *statusCode;
  LassoNodeClass  *statusCode_class;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING(mapping), -1);

  profile = LASSO_PROFILE(mapping);

  /* set the remote provider id from the request */
  profile->remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID", NULL, NULL);
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id found in name_registration request\n");
    ret = -1;
    goto done;
  }

  /* set NameIdentifierMappingResponse */
  profile->response = lasso_name_identifier_mapping_response_new(profile->server->providerID,
								 (gchar *)lassoSamlStatusCodeSuccess,
								 profile->request);
  if (LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building name identifier mapping response\n");
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
