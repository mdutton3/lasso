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
  gchar     *dump = NULL, *parent_dump = NULL;
  LassoNode *node = NULL;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), NULL);

  parent_dump = lasso_profile_dump(LASSO_PROFILE(name_registration), "NameRegistration");
  node = lasso_node_new_from_dump(parent_dump);
  g_free(parent_dump);

  if (name_registration->oldNameIdentifier != NULL) {
    LASSO_NODE_GET_CLASS(node)->new_child(node, "OldNameIdentifier",
					  name_registration->oldNameIdentifier, FALSE);
  }
 
  dump = lasso_node_export(node);
  
  lasso_node_destroy(node);

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
    url = lasso_provider_get_registerNameIdentifierServiceURL(provider, remote_provider_type, NULL);
    if (url == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Register name identifier service url not found\n");
      ret = -1;
      goto done;
    }

    /* Before building the query, rename names of elements and attributes of SPProvidedNameIdentifier, */
    /* IDPProvidedNameIdentifier, OldProvidedNameIdentifier */
    lasso_register_name_identifier_request_rename_attributes_for_query(LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request));
    query = lasso_node_export_to_query(profile->request,
				       profile->server->signature_method,
				       profile->server->private_key);
    if (query == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Error wile building register name identifier request query message\n");
      ret = -1;
      goto done;
    }

    /* build the msg_url */
    profile->msg_url = g_strdup_printf("%s?%s", url, query);
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
    if (url == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Register name identifier service return url not found\n");
      ret = -1;
      goto done;
    }

    query = lasso_node_export_to_query(profile->response,
				       profile->server->signature_method,
				       profile->server->private_key);
    if (query == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Error while building register name identifier response query message\n");
      ret = -1;
      goto done;
    }

    profile->msg_url = g_strdup_printf("%s?%s", url, query);
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
				     gchar                 *remote_providerID)
{
  LassoProfile    *profile;
  LassoNode       *nameIdentifier_node, *local_nameIdentifier_node;
  LassoFederation *federation;
  GError          *err = NULL;
  LassoProvider   *provider = NULL;

  xmlChar *spNameIdentifier,  *spNameQualifier, *spFormat;
  xmlChar *idpNameIdentifier, *idpNameQualifier, *idpFormat;
  xmlChar *oldNameIdentifier = NULL, *oldNameQualifier = NULL, *oldFormat = NULL;

  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);
  g_return_val_if_fail(remote_providerID != NULL, -1);

  profile = LASSO_PROFILE(name_registration);

  /* verify if the identity and session exist */
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

  /* Get federation */
  federation = lasso_identity_get_federation_ref(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    ret = -1;
    goto done;
  }

  /* FIXME : depending on the requester provider type, verify the format of the old name identifier is only federated type */

  switch (profile->provider_type) {
  case lassoProviderTypeSp:
    /* set the new name identifier */
    spNameIdentifier = lasso_build_unique_id(32);
    spNameQualifier  = g_strdup(profile->remote_providerID);
    spFormat         = lassoLibNameIdentifierFormatFederated;

    /* save the new NameIdentifier to update the federation later */
    local_nameIdentifier_node = lasso_saml_name_identifier_new(spNameIdentifier);
    lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(local_nameIdentifier_node), spNameQualifier);
    lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(local_nameIdentifier_node), spFormat);

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
    idpNameIdentifier = lasso_build_unique_id(32);
    idpNameQualifier  = g_strdup(profile->remote_providerID);
    idpFormat         = lassoLibNameIdentifierFormatFederated;

    /* save the new NameIdentifier to update the federation later */
    local_nameIdentifier_node = lasso_saml_name_identifier_new(idpNameIdentifier);
    lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(local_nameIdentifier_node), idpNameQualifier);
    lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(local_nameIdentifier_node), idpFormat);

    nameIdentifier_node = lasso_federation_get_local_nameIdentifier(federation);
    oldNameIdentifier   = lasso_node_get_content(nameIdentifier_node, NULL);
    oldNameQualifier    = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier", NULL);
    oldFormat           = lasso_node_get_attr_value(nameIdentifier_node, "Format", NULL);

    spNameIdentifier = NULL;
    spNameQualifier  = NULL;
    spFormat         = NULL;
    nameIdentifier_node = lasso_federation_get_remote_nameIdentifier(federation);
    if (nameIdentifier_node != NULL) {
      spNameIdentifier = lasso_node_get_content(nameIdentifier_node, NULL);
      spNameQualifier  = lasso_node_get_attr_value(nameIdentifier_node, "NameQualifier", NULL);
      spFormat         = lasso_node_get_attr_value(nameIdentifier_node, "Format", NULL);
    }
    break;

  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }

  /* build a new request object from single logout protocol profile */
  profile->request = lasso_register_name_identifier_request_new(profile->server->providerID,
								idpNameIdentifier,
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

  /* Save name identifier and old name identifier value */
  /* lasso_federation_set_local_nameIdentifier(federation, local_nameIdentifier_node); */
  profile->nameIdentifier              = lasso_node_get_content(local_nameIdentifier_node, NULL);
  name_registration->oldNameIdentifier = oldNameIdentifier;
  oldNameIdentifier                    = NULL;

  done:
  if (idpNameIdentifier != NULL) {
    xmlFree(idpNameIdentifier);
  }
  if (idpNameQualifier != NULL) {
    xmlFree(idpNameQualifier);
  }
  if (idpFormat != NULL) {
    xmlFree(idpFormat);
  }

  if (spNameIdentifier != NULL) {
    xmlFree(spNameIdentifier);
  }
  if (spNameQualifier != NULL) {
    xmlFree(spNameQualifier);
  }
  if (spFormat != NULL) {
    xmlFree(spFormat);
  }

  if (oldNameIdentifier != NULL) {
    xmlFree(oldNameIdentifier);
  }
  if (oldNameQualifier != NULL) {
    xmlFree(oldNameQualifier);
  }
  if (oldFormat != NULL) {
    xmlFree(oldFormat);
  }

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

  /* get the old provided NameIdentifier to load identity dump */
  name_registration->oldNameIdentifier = lasso_node_get_child_content(profile->request,
								      "OldProvidedNameIdentifier", NULL, NULL);

  done :

  return ret;
}

gint
lasso_name_registration_process_response_msg(LassoNameRegistration *name_registration,
					     gchar                 *response_msg,
					     lassoHttpMethod        response_method)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  xmlChar         *statusCodeValue;
  LassoNode       *statusCode, *nameIdentifier_node;
  gint             ret = 0;

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
    message(G_LOG_LEVEL_CRITICAL, "Invalid response method\n");
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

  /* Update federation with the nameIdentifier attribute. NameQualifier is local ProviderID and format is Federated type */
  if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }
  federation = lasso_identity_get_federation_ref(profile->identity, profile->remote_providerID);
  if (LASSO_IS_FEDERATION(federation) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found\n");
    ret = -1;
    goto done;
  }
  nameIdentifier_node = LASSO_NODE(lasso_saml_name_identifier_new(profile->nameIdentifier));
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier_node), profile->server->providerID);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(nameIdentifier_node), lassoLibNameIdentifierFormatFederated);
  lasso_federation_set_local_nameIdentifier(federation, nameIdentifier_node);
  /* FIXME : use a proper way to set the identity dirty */
  profile->identity->is_dirty = TRUE;

  lasso_node_destroy(nameIdentifier_node);

  done:

  return ret;
}

gint
lasso_name_registration_validate_request(LassoNameRegistration *name_registration)
{
  LassoProfile    *profile;
  LassoFederation *federation = NULL;
  LassoNode       *oldProvidedNameIdentifier, *nameIdentifier;
  gint             remote_provider_type;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

  profile = LASSO_PROFILE(name_registration);

  /* verify the register name identifier request */
  if (LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Register Name Identifier request not found\n");
    ret = -1;
    goto done;
  }

  /* set the remote provider id from the request */
  profile->remote_providerID = lasso_node_get_child_content(profile->request, "ProviderID", NULL, NULL);
  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No provider id found in name registration request\n");
    ret = -1;
    goto done;
  }

  /* set register name identifier response */
  profile->response = lasso_register_name_identifier_response_new(profile->server->providerID,
								  (gchar *)lassoSamlStatusCodeSuccess,
								  profile->request);
  if (LASSO_IS_REGISTER_NAME_IDENTIFIER_RESPONSE(profile->response) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building response\n");
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

  /* verify federation */
  federation = lasso_identity_get_federation_ref(profile->identity, profile->remote_providerID);

  oldProvidedNameIdentifier = lasso_node_get_child(profile->request, "OldProvidedNameIdentifier", NULL, NULL);
  if (oldProvidedNameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Old provided name identifier not found\n");
    ret = -1;
    goto done;
  }

  if (lasso_federation_verify_nameIdentifier(federation, oldProvidedNameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "No name identifier\n");
    ret = -1;
    goto done;
  }

  /* update name identifier in federation */
  switch (remote_provider_type) {
    case lassoProviderTypeSp:
    nameIdentifier = lasso_node_get_child(profile->request, "SPProvidedNameIdentifier", NULL, NULL);
    if (nameIdentifier == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Sp provided name identifier not found\n");
      ret = -1;
      goto done;
    }
    break;

    case lassoProviderTypeIdp:
    nameIdentifier = lasso_node_get_child(profile->request, "IDPProvidedNameIdentifier", NULL, NULL);
    if (nameIdentifier == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Idp provided name identifier not found\n");
      ret = -1;
      goto done;
    }
    break;

  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }
  lasso_federation_set_remote_nameIdentifier(federation, nameIdentifier);
  profile->identity->is_dirty = TRUE;

  /* set the new name identifier */
  profile->nameIdentifier = lasso_node_get_content(nameIdentifier, NULL);

  done:

  return ret;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_name_registration_finalize(LassoNameRegistration *name_registration)
{  
  debug("Register Name Identifier object 0x%x finalized ...\n");

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

LassoNameRegistration*
lasso_name_registration_new_from_dump(LassoServer *server,
				      gchar       *dump)
{
  LassoNameRegistration *name_registration;
  LassoProfile          *profile;
  LassoNode             *node_dump, *request_node, *response_node;
  LassoNode             *initial_request_node, *initial_response_node;
  gchar                 *type, *export, *providerID_index_str;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
  g_return_val_if_fail(dump != NULL, NULL);

  name_registration = LASSO_NAME_REGISTRATION(g_object_new(LASSO_TYPE_NAME_REGISTRATION,
				     "server", lasso_server_copy(server),
				     NULL));

  profile = LASSO_PROFILE(name_registration);

  node_dump = lasso_node_new_from_dump(dump);

  /* profile attributes */
  profile->nameIdentifier    = lasso_node_get_child_content(node_dump, "NameIdentifier",
							    lassoLassoHRef, NULL);
  profile->remote_providerID = lasso_node_get_child_content(node_dump, "RemoteProviderID",
							    lassoLassoHRef, NULL);
  profile->msg_url           = lasso_node_get_child_content(node_dump, "MsgUrl",
							    lassoLassoHRef, NULL);
  profile->msg_body          = lasso_node_get_child_content(node_dump, "MsgBody",
							    lassoLassoHRef, NULL);
  profile->msg_relayState    = lasso_node_get_child_content(node_dump, "MsgRelayState",
							    lassoLassoHRef, NULL);

  /* rebuild request */
  request_node = lasso_node_get_child(node_dump, "RegisterNameIdentifierRequest", lassoLibHRef, NULL);
  if (LASSO_IS_NODE(request_node) == TRUE) {
    export = lasso_node_export(request_node);
    profile->request = lasso_register_name_identifier_request_new_from_export(export,
									      lassoNodeExportTypeXml);
    g_free(export);
    lasso_node_destroy(request_node);
  }

  /* rebuild response */
  response_node = lasso_node_get_child(node_dump, "RegisterNameIdentifierResponse", lassoLibHRef, NULL);
  if (response_node != NULL) {
    export = lasso_node_export(response_node);
    profile->response = lasso_register_name_identifier_response_new_from_export(export,
										lassoNodeExportTypeXml);
    g_free(export);
    lasso_node_destroy(response_node);
  }
  
  /* provider type */
  type = lasso_node_get_child_content(node_dump, "ProviderType", lassoLassoHRef, NULL);
  profile->provider_type = atoi(type);
  xmlFree(type);

  /* name registration attributes */
  name_registration->oldNameIdentifier = lasso_node_get_child_content(node_dump, "OldNameIdentifier",
								      lassoLassoHRef, NULL);

  return name_registration;
}
