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

#include <lasso/environs/register_name_identifier.h>

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_register_name_identifier_dump:
 * @register_name_identifier: the register name identifier object
 * 
 * This method builds a dump of the register name identifier object
 * 
 * Return value: a newly allocated string or NULL
 **/
gchar *
lasso_register_name_identifier_dump(LassoRegisterNameIdentifier *register_name_identifier)
{
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), NULL);

  dump = NULL;

  return(dump);
}

/**
 * lasso_register_name_identifier_build_request_msg:
 * @register_name_identifier: the register name identifier object
 * 
 * This method build a register name identifier request message.
 * 
 * It gets the register name identifier protocol profile and :
 *    if it is a SOAP method, then it builds the register name identifier request SOAP message,
 *    optionaly signs his node, set the msg_body attribute, gets the SoapEndpoint
 *    url and set the msg_url attribute.
 *
 *    if it is a HTTP-Redirect method, then it builds the register name identifier request QUERY message
 *    ( optionaly signs the request message ), builds the request url with register name identifier url
 *    with register name identifier service url, set the msg_url attribute of the register name identifier
 *    object, set the msg_body to NULL.
 * 
 * Return value: 0 if OK else < 0
 **/
gint
lasso_register_name_identifier_build_request_msg(LassoRegisterNameIdentifier *register_name_identifier)
{
  LassoProfile  *profile;
  LassoProvider *provider;
  xmlChar       *protocolProfile;
  gint           ret = 0;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  
  profile = LASSO_PROFILE(register_name_identifier);

  /* get the provider */
  provider = lasso_server_get_provider_ref(profile->server,
					   profile->remote_providerID,
					   NULL);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider %s not found\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  /* get the prototocol profile of the register_name_identifier */
  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider,
									     lassoProviderTypeIdp,
									     NULL);
  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Register_Name_Identifier Protocol profile not found\n");
    ret = -1;
    goto done;
  }

  if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileRniIdpSoap) || \
      xmlStrEqual(protocolProfile, lassoLibProtocolProfileRniSpSoap)) {
    profile->request_type = lassoHttpMethodSoap;
    /* sign the request message */
    lasso_samlp_request_abstract_set_signature(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request),
					       profile->server->signature_method,
					       profile->server->private_key,
					       profile->server->certificate);
    
    /* build the registration request message */
    profile->msg_url  = lasso_provider_get_soapEndpoint(provider,
							lassoProviderTypeIdp,
							NULL);
    profile->msg_body = lasso_node_export_to_soap(profile->request);
  }
  else if (xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniIdpHttp) || \
	   xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniSpHttp)) {
    /* temporary vars to store url, query and separator */
    gchar *url, *query;
    const gchar *separator = "?";

    /* build and optionaly sign the query message and build the register name identifier request url */
    url = lasso_provider_get_singleLogoutServiceURL(provider, profile->provider_type, NULL);
    query = lasso_node_export_to_query(profile->request,
				       profile->server->signature_method,
				       profile->server->private_key);
    profile->msg_url = g_strjoin(separator, url, query);
    profile->msg_body = NULL;
    xmlFree(url);
    xmlFree(query);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid protocol Profile for register name identifier\n");
    ret = -1;
    goto done;
  }

  done:

  return(ret);
}

gint
lasso_register_name_identifier_build_response_msg(LassoRegisterNameIdentifier *register_name_identifier)
{
  LassoProfile *profile;
  LassoProvider *provider;
  xmlChar *protocolProfile;
  
  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);

  profile = LASSO_PROFILE(register_name_identifier);

  provider = lasso_server_get_provider_ref(profile->server,
					   profile->remote_providerID,
					   NULL);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider not found (ProviderID = %s)\n", profile->remote_providerID);
    return(-2);
  }

  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider,
									     lassoProviderTypeSp,
									     NULL);
  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Register name identifier protocol profile not found\n");
    return(-3);
  }

  if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
      xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    debug("building a soap response message\n");
    profile->msg_url = lasso_provider_get_registerNameIdentifierServiceURL(provider,
									   lassoProviderTypeSp,
									   NULL);
    profile->msg_body = lasso_node_export_to_soap(profile->response);
  }
  else if (xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	   xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    debug("building a http get response message\n");
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
  LassoProfile    *profile;
  LassoNode       *nameIdentifier_node;
  LassoFederation *federation;

  xmlChar *spNameIdentifier,  *spNameQualifier, *spFormat;
  xmlChar *idpNameIdentifier, *idpNameQualifier, *idpFormat;
  xmlChar *oldNameIdentifier = NULL, *oldNameQualifier = NULL, *oldFormat = NULL;

  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);

  profile = LASSO_PROFILE(register_name_identifier);

  if (remote_providerID == NULL) {
    message(G_LOG_LEVEL_INFO, "No remote provider id, get the next federation peer provider id\n");
    profile->remote_providerID = lasso_identity_get_next_federation_remote_providerID(profile->identity);
  }
  else {
    message(G_LOG_LEVEL_INFO, "A remote provider id for register name identifier request : %s\n", remote_providerID);
    profile->remote_providerID = g_strdup(remote_providerID);
  }
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id for init request\n");
    ret = -1;
    goto done;
  }

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    ret = -1;
    goto done;
  }
  switch (profile->provider_type) {
  case lassoProviderTypeSp:
    /* set the new name identifier */
    spNameIdentifier = lasso_build_unique_id(32);
    spNameQualifier  = g_strdup(profile->remote_providerID);
    spFormat         = "federated";

    /* set the old name identifier */
    nameIdentifier_node = lasso_federation_get_local_nameIdentifier(federation);
    if (nameIdentifier_node != NULL) {
      oldNameIdentifier = lasso_node_get_content(nameIdentifier_node, NULL);
      oldNameQualifier  = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier", NULL);
      oldFormat         = lasso_node_get_attr_value(nameIdentifier_node, "Format", NULL);
    }
    lasso_node_destroy(nameIdentifier_node);

    /* idp name identifier */
    nameIdentifier_node = lasso_federation_get_remote_nameIdentifier(federation);
    if (nameIdentifier_node == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Remote NameIdentifier for service provider not found\n");
      ret = -1;
      goto done;
    }
    idpNameIdentifier   = lasso_node_get_content(nameIdentifier_node, NULL);
    idpNameQualifier    = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier", NULL);
    idpFormat           = lasso_node_get_attr_value(nameIdentifier_node, "Format", NULL);
    lasso_node_destroy(nameIdentifier_node);

    /* if old name identifier (Service provider) not found, set with federation provider */
    if (oldNameIdentifier == NULL) {
      oldNameIdentifier = g_strdup(idpNameIdentifier);
      oldNameQualifier  = g_strdup(idpNameQualifier);
      oldFormat         = g_strdup(idpFormat);
    }
    break;

  case lassoProviderTypeIdp:
    debug("Federation Provider\n");
    idpNameIdentifier = lasso_build_unique_id(32);
    idpNameQualifier  = g_strdup(profile->remote_providerID);
    idpFormat         = "federated";

    nameIdentifier_node = lasso_federation_get_local_nameIdentifier(federation);
    oldNameIdentifier   = lasso_node_get_content(nameIdentifier_node, NULL);
    oldNameQualifier    = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier", NULL);
    oldFormat           = lasso_node_get_attr_value(nameIdentifier_node, "Format", NULL);

    nameIdentifier_node = lasso_federation_get_remote_nameIdentifier(federation);
    if (nameIdentifier_node != NULL) {
      spNameIdentifier = lasso_node_get_content(nameIdentifier_node, NULL);
      spNameQualifier  = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier", NULL);
      spFormat         = lasso_node_get_attr_value(nameIdentifier_node, "Format", NULL);
    }
    else{
      spNameIdentifier = g_strdup(oldNameIdentifier);
      spNameQualifier  = g_strdup(oldNameQualifier);
      spFormat         = g_strdup(oldFormat);
    }
    break;

  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type (%d)\n", profile->provider_type);
    ret = -1;
    goto done;
  }
  lasso_federation_destroy(federation);

  debug("old name identifier : %s, old name qualifier : %s, old format : %s\n", oldNameIdentifier, oldNameQualifier, oldFormat);
  debug("sp name identifier : %s, sp name qualifier : %s, sp format : %s\n",    spNameIdentifier,  spNameQualifier,  spFormat);
  debug("idp name identifier : %s, idp name qualifier : %s, idp format : %s\n", idpNameIdentifier, idpNameQualifier, idpFormat);

  profile->request = lasso_register_name_identifier_request_new(profile->server->providerID,
								idpNameQualifier,
								idpNameQualifier,
								idpFormat,
								spNameIdentifier,
								spNameQualifier,
								spFormat,
								oldNameIdentifier,
								oldNameQualifier,
								oldFormat);

  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while creating the request\n");
    ret = -1;
    goto done;
  }

  done:

  return(ret);
}

gint lasso_register_name_identifier_process_request_msg(LassoRegisterNameIdentifier *register_name_identifier,
							gchar                       *request_msg,
							lassoHttpMethod              request_method)
{
  LassoProfile *profile;
  gint          ret = 0;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  g_return_val_if_fail(request_msg!=NULL, -1);

  profile = LASSO_PROFILE(register_name_identifier);

  switch (request_method) {
  case lassoHttpMethodSoap:
    debug("Build a register name identifier request from soap msg\n");
    profile->request = lasso_register_name_identifier_request_new_from_export(request_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    debug("Build a register name identifier request from query msg\n");
    profile->request = lasso_register_name_identifier_request_new_from_export(request_msg, lassoNodeExportTypeQuery);
    break;
  case lassoHttpMethodGet:
    debug("TODO, implement the get method\n");
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid request method\n");
    ret = -1;
    goto done;
  }
  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the request from msg\n");
    ret = -1;
    goto done;
  }

  /* get the NameIdentifier to load identity dump */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier", NULL, NULL);

  /* get the RelayState */
  profile->msg_relayState = lasso_node_get_child_content(profile->request,
							 "RelayState", NULL, NULL);

  done :

  return(ret);
}

gint
lasso_register_name_identifier_validate_request(LassoRegisterNameIdentifier *register_name_identifier)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  LassoNode       *nameIdentifier, *assertion;
  LassoNode       *statusCode;
  LassoNodeClass  *statusCode_class;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);

  profile = LASSO_PROFILE(register_name_identifier);

  /* set the remote provider id from the request */
  profile->remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID", NULL, NULL);
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id found in register_name_identifier request\n");
    ret = -1;
    goto done;
  }

  /* set RegisterNameIdentifierResponse */
  profile->response = lasso_register_name_identifier_response_new(profile->server->providerID,
								  (gchar *)lassoSamlStatusCodeSuccess,
								  profile->request);

  if (profile->response == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building response\n");
    ret = -1;
    goto done;
  }

  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  statusCode_class = LASSO_NODE_GET_CLASS(statusCode);

  nameIdentifier = lasso_node_get_child(profile->request, "NameIdentifier", NULL, NULL);
  if (nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No name identifier found in register_name_identifier request\n");
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  /* Verify federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_WARNING, "No federation for %s\n", profile->remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }

  if (lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_WARNING, "No name identifier for %s\n", profile->remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoLibStatusCodeFederationDoesNotExist);
    ret = -1;
    goto done;
  }
  lasso_federation_destroy(federation);

  /* verify authentication (if ok, delete assertion) */
  assertion = lasso_session_get_assertion(profile->session, profile->remote_providerID);
  if (assertion == NULL) {
    message(G_LOG_LEVEL_WARNING, "%s has no assertion\n", profile->remote_providerID);
    statusCode_class->set_prop(statusCode, "Value", lassoSamlStatusCodeRequestDenied);
    lasso_node_destroy(assertion);
    ret = -1;
    goto done;
  }

  done:

  return(ret);
}

gint
lasso_register_name_identifier_process_response_msg(LassoRegisterNameIdentifier *register_name_identifier,
						    gchar                       *response_msg,
						    lassoHttpMethod              response_method)
{
  LassoProfile *profile;
  xmlChar      *statusCodeValue;
  LassoNode    *statusCode;
  gint          ret = 0;

  g_return_val_if_fail(LASSO_IS_REGISTER_NAME_IDENTIFIER(register_name_identifier), -1);
  g_return_val_if_fail(response_msg != NULL, -1);

  profile = LASSO_PROFILE(register_name_identifier);

  /* parse RegisterNameIdentifierResponse */
  switch (response_method) {
  case lassoHttpMethodSoap:
    profile->response = lasso_register_name_identifier_response_new_from_export(response_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    profile->response = lasso_register_name_identifier_response_new_from_export(response_msg, lassoNodeExportTypeQuery);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Unknown response method\n");
    ret = -1;
    goto done;
  }
 
  statusCode = lasso_node_get_child(profile->response, "StatusCode", NULL, NULL);
  if (statusCode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "StatusCode not found\n");
    ret = -1;
    goto done;
  }
  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value", NULL);
  if (statusCodeValue == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "StatusCodeValue not found\n");
    ret = -1;
    goto done;
  }

  if(!xmlStrEqual(statusCodeValue, lassoSamlStatusCodeSuccess)) {
    ret = -1;
    goto done;
  }

  done:

  return(ret);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_register_name_identifier_finalize(LassoRegisterNameIdentifier *register_name_identifier)
{  
  message(G_LOG_LEVEL_INFO, "Register Name Identifier object 0x%x finalized ...\n", register_name_identifier);

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
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoRegisterNameIdentifier",
				       &this_info, 0);
  }
  return this_type;
}

LassoRegisterNameIdentifier *
lasso_register_name_identifier_new(LassoServer       *server,
				   lassoProviderType  provider_type)
{
  LassoRegisterNameIdentifier *register_name_identifier;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the register_name_identifier object */
  register_name_identifier = g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER,
					  "server", lasso_server_copy(server),
					  "provider_type", provider_type,
					  NULL);

  return(register_name_identifier);
}
