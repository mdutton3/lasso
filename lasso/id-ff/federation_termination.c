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

#include <lasso/environs/federation_termination.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_federation_termination_build_notification_msg:
 * @defederation: the federation termination object
 * 
 * This method builds the federation termination notification message.
 * 
 * It gets the federation termination notification protocol profile and :
 *    if it is a SOAP method, then it builds the federation termination notification SOAP message,
 *    optionaly signs the notification node, set the msg_body attribute, gets the SoapEndpoint
 *    url and set the msg_url attribute of the federation termination object.
 *
 *    if it is a HTTP-Redirect method, then it builds the federation termination notification QUERY message
 *    ( optionaly signs the notification message ), builds the federation termination notification url
 *    with federation termination service url, set the msg_url attribute of the federation termination object,
 *    set the msg_body to NULL
 * 
 * Return value: O of OK else < 0
 **/
gint
lasso_federation_termination_build_notification_msg(LassoFederationTermination *defederation)
{
  LassoProfile      *profile;
  LassoProvider     *provider;
  xmlChar           *protocolProfile;
  gint               ret = 0;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);
  
  profile = LASSO_PROFILE(defederation);

  provider = lasso_server_get_provider_ref(profile->server,
					   profile->remote_providerID,
					   NULL);

  /* get the protocol profile of the remote provider ( if the notifier is a IDP, then get with IDP type else if IDP, SP ) */
  if (profile->provider_type == lassoProviderTypeSp) {
  protocolProfile = lasso_provider_get_federationTerminationNotificationProtocolProfile(provider,
											lassoProviderTypeIdp,
											NULL);
  }
  else if (profile->provider_type == lassoProviderTypeIdp) {
  protocolProfile = lasso_provider_get_federationTerminationNotificationProtocolProfile(provider,
											lassoProviderTypeSp,
											NULL);    
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
    ret = -1;
    goto done;
  }

  if (protocolProfile == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation termination notification protocol profile not found\n");
    ret = -1;
    goto done;
  }

  /* build the federation termination notification message (SOAP or HTTP-Redirect) */
  if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloSpSoap) || \
      xmlStrEqual(protocolProfile, lassoLibProtocolProfileSloIdpSoap)) {
    /* optionaly sign the notification node */
    if (profile->server->private_key != NULL && profile->server->signature_method && profile->server->certificate) {
      lasso_samlp_request_abstract_set_signature(LASSO_SAMLP_REQUEST_ABSTRACT(profile->request),
						 profile->server->signature_method,
						 profile->server->private_key,
						 profile->server->certificate);
    }

    /* build the message */
    profile->msg_url = lasso_provider_get_federationTerminationServiceURL(provider,
									  lassoProviderTypeIdp,
									  NULL);
    if (profile->msg_url == NULL) {
      message(G_LOG_LEVEL_CRITICAL, "Federation Termination Notification url not found\n");
      ret = -1;
      goto done;
    }
    profile->msg_body = lasso_node_export_to_soap(profile->request);
  }
  else if (xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloSpHttp) || \
	   xmlStrEqual(protocolProfile,lassoLibProtocolProfileSloIdpHttp)) {
    /* temporary vars to store url, query and separator */
    gchar *url, *query;
    const gchar *separator = "?";

    /* build and optionaly sign the query message and build the federation termination notification url */
    url = lasso_provider_get_federationTerminationServiceURL(provider,
							     lassoProviderTypeIdp,
							     NULL);
    query = lasso_node_export_to_query(profile->request,
				       profile->server->signature_method,
				       profile->server->private_key);
    profile->msg_url = g_strjoin(separator, url, query);
    profile->msg_body = NULL;
    xmlFree(url);
    xmlFree(query);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, "Invalid federation termination notification protocol profile\n");
    ret = -1;
    goto done;
  }

  done:
  if (provider != NULL) {
    lasso_provider_destroy(provider);
  }
  if (protocolProfile != NULL) {
    xmlFree(protocolProfile);
  }

  return(ret);
}

/**
 * lasso_federation_termination_destroy:
 * @defederation: the federation termination object
 * 
 * This method destroys the federation termination object
 *
 **/
void
lasso_federation_termination_destroy(LassoFederationTermination *defederation)
{
  g_object_unref(G_OBJECT(defederation));
}

/**
 * lasso_federation_termination_init_notification:
 * @defederation: the federation termination object
 * @remote_providerID: the provider id of the federation termination notified provider.
 *    If it is set to NULL, then gets the default first remote provider id.
 *
 * It sets a new federation termination notification to the remote provider id
 * with the provider id of the requester (from the server object )
 * and the name identifier of the federated principal
 * 
 * Return value: 0 if OK else < 0
 **/
gint
lasso_federation_termination_init_notification(LassoFederationTermination *defederation,
					       gchar                      *remote_providerID)
{
  LassoProfile    *profile;
  LassoFederation *federation;
  LassoNode       *nameIdentifier = NULL;
  xmlChar         *content = NULL, *nameQualifier = NULL, *format = NULL;
  gint             ret = 0;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);

  profile = LASSO_PROFILE(defederation);

  if (remote_providerID == NULL) {
    debug("No remote provider id, get the remote provider id of the first federation\n");
    profile->remote_providerID = lasso_identity_get_next_federation_remote_providerID(profile->identity);
  }
  else {
    debug("A remote provider id for defederation notification : %s\n", remote_providerID);
    profile->remote_providerID = g_strdup(remote_providerID);
  }

  if (profile->remote_providerID == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No remote provider id to build the federation termination notification\n");
    ret = -1;
    goto done;
  }

  /* get federation */
  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Federation not found for %s\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  /* get the name identifier (!!! depend on the provider type : SP or IDP !!!) */
  switch (profile->provider_type) {
  case lassoProviderTypeSp:
    nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
    if (!nameIdentifier) {
      nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
    }
    break;
  case lassoProviderTypeIdp:
    nameIdentifier = LASSO_NODE(lasso_federation_get_remote_nameIdentifier(federation));
    if (!nameIdentifier) {
      nameIdentifier = LASSO_NODE(lasso_federation_get_local_nameIdentifier(federation));
    }
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid provider type\n");
  }

  if (!nameIdentifier) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found for %s\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  /* build the request */
  content = lasso_node_get_content(nameIdentifier, NULL);
  nameQualifier = lasso_node_get_attr_value(nameIdentifier, "NameQualifier", NULL);
  format = lasso_node_get_attr_value(nameIdentifier, "Format", NULL);
  profile->request = lasso_federation_termination_notification_new(profile->server->providerID,
								   content,
								   nameQualifier,
								   format);

  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while creating the notification\n");
    ret = -1;
    goto done;
  }

  done:
  if (federation!=NULL) {
    lasso_federation_destroy(federation);
  }

  /* destroy allocated objects */
  xmlFree(content);
  xmlFree(nameQualifier);
  xmlFree(format);
  lasso_node_destroy(nameIdentifier);

  return(ret);
}

/**
 * lasso_federation_termination_process_notification_msg:
 * @defederation: the federation termination object
 * @notification_msg: the federation termination notification message
 * @notification_method: the federation termination notification method
 * 
 * Process the federation termination notification.
 *    If it is a SOAP notification method then it builds the federation termination object
 *    from the SOAP message and optionaly verify the signature.
 *
 *    if it is a HTTP-Redirect notification method the nit builds the federation termination notication
 *    object from the QUERY message and optionaly verify the signature
 * 
 * Set the msg_nameIdentifier attribute with the NameIdentifier content of the notification object and
 * optionaly set the msg_relayState attribute with the RelayState content of the notifcation object
 *
 * Return value: 0 if OK else < 0
 **/
gint
lasso_federation_termination_process_notification_msg(LassoFederationTermination *defederation,
						      gchar                      *notification_msg,
						      lassoHttpMethod             notification_method)
{
  LassoProfile *profile;
  gint ret = 0;

  g_return_val_if_fail(LASSO_IS_FEDERATION_TERMINATION(defederation), -1);
  g_return_val_if_fail(notification_msg!=NULL, -1);

  profile = LASSO_PROFILE(defederation);

  switch (notification_method) {
  case lassoHttpMethodSoap:
    debug("Build a federation termination notification from soap msg\n");
    profile->request = lasso_federation_termination_notification_new_from_export(notification_msg, lassoNodeExportTypeSoap);
    break;
  case lassoHttpMethodRedirect:
    debug("Build a federation termination notification from query msg\n");
    profile->request = lasso_federation_termination_notification_new_from_export(notification_msg, lassoNodeExportTypeQuery);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid notification method\n");
    ret = -1;
    goto done;
  }
  if (profile->request==NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Error while building the notification from msg\n");
    ret = -1;
    goto done;
  }

  /* set the http request method */
  profile->http_request_method = notification_method;

  /* get the NameIdentifier */
  profile->nameIdentifier = lasso_node_get_child_content(profile->request,
							 "NameIdentifier", NULL, NULL);
  if (profile->nameIdentifier==NULL) {
    message(G_LOG_LEVEL_CRITICAL, "NameIdentifier not found\n");
    ret = -1;
    goto done;
  }

  /* get the RelayState */
  profile->msg_relayState = lasso_node_get_child_content(profile->request,
							 "RelayState", NULL, NULL);

  done:

  return(ret);
}

/**
 * lasso_federation_termination_validate_notification:
 * @defederation: the federation termination object
 * 
 * Validate the federation termination notification :
 *    verifies the ProviderID
 *    if HTTP-Redirect method, set msg_url with the federation termination service return url
 *    verifies the federation
 *    verifies the authentication
 * 
 * Return value: O if OK else < 0
 **/
gint
lasso_federation_termination_validate_notification(LassoFederationTermination *defederation)
{
  LassoProfile    *profile;
  LassoProvider   *provider;
  LassoFederation *federation;
  LassoNode       *nameIdentifier;
  gint             ret = 0;
  gint             signature_check;
  GError          *err = NULL;

  profile = LASSO_PROFILE(defederation);

  if (profile->request == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Request not found\n");
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

  /* if HTTP-Redirect protocol profile, set the federation termination service return url */
  profile->msg_url  = NULL;
  profile->msg_body = NULL;
  provider = lasso_server_get_provider(profile->server, profile->remote_providerID, NULL);
  if (provider == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Provider not found\n");
    ret = -1;
    goto done;
  }
  if (profile->http_request_method==lassoHttpMethodRedirect) {
    profile->msg_url = lasso_provider_get_federationTerminationServiceReturnURL(provider,
										profile->provider_type,
										NULL);
    if (profile->msg_url) {
      message(G_LOG_LEVEL_CRITICAL, "Federation termination service return url not found\n");
      ret = -1;
      goto done;
    }
  }

  nameIdentifier = lasso_node_get_child(profile->request,
					"NameIdentifier",
					NULL,
					NULL);
  if (nameIdentifier == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Name identifier not found in request\n");
    ret = -1;
    goto done;
  }

  /* Verify federation */
  if (profile->identity == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Identity not found\n");
    ret = -1;
    goto done;
  }

  federation = lasso_identity_get_federation(profile->identity, profile->remote_providerID);
  if (federation == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "No federation for %s\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  if (lasso_federation_verify_nameIdentifier(federation, nameIdentifier) == FALSE) {
    message(G_LOG_LEVEL_CRITICAL, "No name identifier for %s\n", profile->remote_providerID);
    ret = -1;
    goto done;
  }

  /* remove federation of the remote provider */
  lasso_identity_remove_federation(profile->identity, profile->remote_providerID);

  done:
  if (federation!=NULL) {
    lasso_federation_destroy(federation);
  }
  if (nameIdentifier!=NULL) {
    lasso_node_destroy(nameIdentifier);
  }

  return(ret);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_federation_termination_instance_init(LassoFederationTermination *defederation)
{
}

static void
lasso_federation_termination_class_init(LassoFederationTerminationClass *class)
{
}

GType lasso_federation_termination_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoFederationTerminationClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_federation_termination_class_init,
      NULL,
      NULL,
      sizeof(LassoFederationTermination),
      0,
      (GInstanceInitFunc) lasso_federation_termination_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				       "LassoFederationTermination",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_federation_termination_new:
 * @server: the server object of the provider
 * @provider_type: the provider type (service provider or identity provider)
 * 
 * This function build a new federation termination object to build
 * a notification message or to process a notification.
 *
 * If building a federation termination notification message then call :
 *    lasso_federation_termination_init_notification()
 *    lasso_federation_termination_build_notification_msg()
 * and get msg_url or msg_body.
 *
 * If processing a federation termination notification message then call :
 *   lasso_federation_termination_process_notification_msg()
 *   lasso_federation_termination_validate_notification()
 * and process the returned code.
 *
 * Return value: a new instance of federation termination object or NULL
 **/
LassoFederationTermination*
lasso_federation_termination_new(LassoServer *server,
				 gint         provider_type)
{
  LassoFederationTermination *defederation;

  g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

  /* set the federation_termination object */
  defederation = g_object_new(LASSO_TYPE_FEDERATION_TERMINATION,
			      "server", lasso_server_copy(server),
			      "provider_type", provider_type,
			      NULL);

  return(defederation);
}
