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

#include <string.h>
#include <glib/gprintf.h>

#include <lasso/environs/name_registration.h>

#include <lasso/xml/errors.h>

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_name_registration_dump:
 * @name_registration: the register name identifier object
 * 
 * This method builds a dump of the register name identifier object
 * 
 * Return value: a newly allocated string or NULL
 **/
gchar *
lasso_name_registration_dump(LassoNameRegistration *name_registration)
{
  gchar *dump;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), NULL);

  dump = NULL;

  return dump;
}

/**
 * lasso_name_registration_build_request_msg:
 * @name_registration: the register name identifier object
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
lasso_name_registration_build_request_msg(LassoNameRegistration *name_registration)
{
  LassoProfile     *profile;
  LassoProvider    *provider;
  xmlChar          *protocolProfile = NULL;
  GError           *err = NULL;
  gchar            *url = NULL, *query = NULL;
  lassoProviderType remote_provider_type;
  gint              ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);
  
  profile = LASSO_PROFILE(name_registration);

  /* get the remote provider type and get the remote provider object */
  if (profile->provider_type == lassoProviderTypeSp) {
    remote_provider_type = lassoProviderTypeIdp;
  }
  else if (profile->provider_type == lassoProviderTypeIdp) {
    remote_provider_type = lassoProviderTypeSp;
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }
  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* get the prototocol profile of the name_registration */
  protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider,
									     remote_provider_type,
									     NULL);
  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name_Registration Protocol profile not found\n");
    ret = -1;
    goto done;
  }

  /* build the register name identifier request message */
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
							remote_provider_type,
							NULL);
    profile->msg_body = lasso_node_export_to_soap(profile->request);
  }
  else if (xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniIdpHttp) || \
	   xmlStrEqual(protocolProfile,lassoLibProtocolProfileRniSpHttp)) {
    /* build and optionaly sign the query message and build the register name identifier request url */
    url = lasso_provider_get_registerNameIdentifierServiceURL(provider, profile->provider_type, NULL);
    query = lasso_node_export_to_query(profile->request,
				       profile->server->signature_method,
				       profile->server->private_key);

    if ( (url == NULL) || (query == NULL) ) {
      message(G_LOG_LEVEL_CRITICAL, "Error while building request QUERY url\n");
      ret = -1;
      goto done;
    }

    /* build the msg_url */
    profile->msg_url = g_new(gchar, strlen(url)+strlen(query)+1+1);
    g_sprintf(profile->msg_url, "%s?%s", url, query);
    profile->msg_body = NULL;
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid register name identifier protocol Profile \n");
    ret = -1;
    goto done;
  }

  done:
  if (protocolProfile != NULL) {
    xmlFree(protocolProfile);
  }
  if (url != NULL) {
    xmlFree(url);
  }
  if (query != NULL) {
    xmlFree(query);
  }

  return ret;
}

gint
lasso_name_registration_build_response_msg(LassoNameRegistration *name_registration)
{
  LassoProfile     *profile;
  LassoProvider    *provider;
  xmlChar          *protocolProfile;
  gchar            *url = NULL, *query = NULL;
  GError           *err = NULL;
  lassoProviderType remote_provider_type;
  gint              ret = 0;
  
  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

  profile = LASSO_PROFILE(name_registration);

  /* get the provider */
  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    return ret;
  }

  /* get the remote provider type */
  if (profile->provider_type == lassoProviderTypeSp) {
    remote_provider_type = lassoProviderTypeIdp;
  }
  else if (profile->provider_type == lassoProviderTypeIdp) {
    remote_provider_type = lassoProviderTypeSp;
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    return -1;
  }

  /* build register name identifier message */
  switch (profile->http_request_method) {
  case lassoHttpMethodSoap:
    profile->msg_url = NULL;
    profile->msg_body = lasso_node_export_to_soap(profile->response);
    break;
  case lassoHttpMethodRedirect:
    url = lasso_provider_get_registerNameIdentifierServiceReturnURL(provider, remote_provider_type, NULL);
    query = lasso_node_export_to_query(profile->response,
				       profile->server->signature_method,
				       profile->server->private_key);
    if ( (url == NULL) || (query == NULL) ) {
      message(G_LOG_LEVEL_CRITICAL, "Url %s or query %s not found\n", url, query);
      ret = -1;
      goto done;
    }

    profile->msg_url = g_new(gchar, strlen(url)+strlen(query)+1+1);
    g_sprintf(profile->msg_url, "%s?%s", url, query);
    profile->msg_body = NULL;
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP request method\n");
    ret = -1;
    goto done;
  }

  done:
  if (url != NULL) {
    g_free(url);
  }
  if (query != NULL) {
    g_free(query);
  }

  return 0;
}

void
lasso_name_registration_destroy(LassoNameRegistration *name_registration)
{
  g_object_unref(G_OBJECT(name_registration));
}

gint
lasso_name_registration_init_request(LassoNameRegistration *name_registration,
				     gchar                 *remote_providerID,
				     lassoHttpMethod        request_method)
{
  LassoProfile    *profile;
  LassoNode       *nameIdentifier_node;
  LassoFederation *federation;
  xmlChar         *protocolProfile = NULL;
  GError          *err = NULL;
  LassoProvider   *provider = NULL;

  xmlChar *spNameIdentifier,  *spNameQualifier, *spFormat;
  xmlChar *idpNameIdentifier, *idpNameQualifier, *idpFormat;
  xmlChar *oldNameIdentifier = NULL, *oldNameQualifier = NULL, *oldFormat = NULL;

  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

  profile = LASSO_PROFILE(name_registration);

  /* verify if the identity and session exist */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }
  if (profile->session == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Session not found\n");
    ret = -1;
    goto done;
  }

  /* get the remote provider id */
  /* If remote_providerID is NULL, then get the first remote provider id in session */
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

  /* get the provider */
  provider = lasso_server_get_provider_ref(profile->server, profile->remote_providerID, &err);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, err->message);
    ret = err->code;
    g_error_free(err);
    goto done;
  }

  /* Get the single logout protocol profile */
  if (profile->provider_type == lassoProviderTypeIdp) {
    protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider, lassoProviderTypeSp, NULL);
  }
  else if (profile->provider_type == lassoProviderTypeSp) {
    protocolProfile = lasso_provider_get_registerNameIdentifierProtocolProfile(provider, lassoProviderTypeIdp, NULL);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }
  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Single logout protocol profile not found\n");
    ret = -1;
    goto done;
  }

  /* build a new request object from single logout protocol profile */
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

  return ret;
}

gint lasso_name_registration_process_request_msg(LassoNameRegistration *name_registration,
						 gchar                 *request_msg,
						 lassoHttpMethod        request_method)
{
  LassoProfile *profile;
  gint          ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);
  g_return_val_if_fail(request_msg != NULL, -1);

  profile = LASSO_PROFILE(name_registration);
  
  /* rebuild the request message and optionaly verify the signature */
  switch (request_method) {
  case lassoHttpMethodSoap:
    profile->request = lasso_register_name_identifier_request_new_from_export(request_msg, lassoNodeExportTypeSoap);
    if (LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request) == FALSE) {
      message(G_LOG_LEVEL_CRITICAL, "Message is not a RegisterNameIdentifierRequest\n");
      ret = -1;
      goto done;
    }
    break;
  case lassoHttpMethodRedirect:
    profile->request = lasso_register_name_identifier_request_new_from_export(request_msg, lassoNodeExportTypeQuery);
    if (LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request) == FALSE) {
      ret = LASSO_PROFILE_ERROR_INVALID_QUERY;
      goto done;
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid request method\n");
    ret = -1;
    goto done;
  }

  /* set the http request method */
  profile->http_request_method = request_method;

  /* get the NameIdentifier to load identity dump */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier", NULL, NULL);

  done :

  return ret;
}

gint
lasso_name_registration_process_response_msg(LassoNameRegistration *name_registration,
						    gchar                       *response_msg,
						    lassoHttpMethod              response_method)
{
  LassoProfile *profile;
  xmlChar      *statusCodeValue;
  LassoNode    *statusCode;
  gint          ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);
  g_return_val_if_fail(response_msg != NULL, -1);

  profile = LASSO_PROFILE(name_registration);

  /* parse NameRegistrationResponse */
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

  return ret;
}


gint
lasso_name_registration_validate_request(LassoNameRegistration *name_registration)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  LassoNode       *nameIdentifier, *assertion;
  LassoNode       *statusCode;
  LassoNodeClass  *statusCode_class;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

  profile = LASSO_PROFILE(name_registration);

  /* set the remote provider id from the request */
  profile->remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID", NULL, NULL);
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id found in name_registration request\n");
    ret = -1;
    goto done;
  }

  /* set NameRegistrationResponse */
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
    message(G_LOG_LEVEL_CRITICAL, "No name identifier found in name_registration request\n");
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

  return ret;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_name_registration_finalize(LassoNameRegistration *name_registration)
{  
  message(G_LOG_LEVEL_INFO, "Register Name Identifier object 0x%x finalized ...\n", name_registration);

  parent_class->finalize(G_OBJECT(name_registration));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_name_registration_instance_init(LassoNameRegistration *name_registration)
{
}

static void
lasso_name_registration_class_init(LassoNameRegistrationClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* override parent class methods */
  gobject_class->finalize = (void *)lasso_name_registration_finalize;
}

GType lasso_name_registration_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoNameRegistrationClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_name_registration_class_init,
      NULL,
      NULL,
      sizeof(LassoNameRegistration),
      0,
      (GInstanceInitFunc) lasso_name_registration_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoNameRegistration",
				       &this_info, 0);
  }
  return this_type;
}

LassoNameRegistration *
lasso_name_registration_new(LassoServer       *server,
				   lassoProviderType  provider_type)
{
  LassoNameRegistration *name_registration;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the name_registration object */
  name_registration = g_object_new(LASSO_TYPE_NAME_REGISTRATION,
					  "server", lasso_server_copy(server),
					  "provider_type", provider_type,
					  NULL);

  return name_registration;
}
