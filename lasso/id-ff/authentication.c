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

#include <lasso/xml/samlp_response.h>
#include <lasso/protocols/request.h>
#include <lasso/protocols/response.h>
#include <lasso/protocols/authn_response.h>
#include <lasso/environs/authentication.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar *
lasso_authentication_build_request_msg(LassoAuthentication *authn)
{
  LassoProvider *provider;
  xmlChar *request_protocolProfile, *url, *query;
  gchar *request_msg;
  gboolean must_sign;
  
  provider = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(authn)->server,
				       LASSO_PROFILE_CONTEXT(authn)->local_providerID);
  if (provider == NULL) {
    return (NULL);
  }  
  must_sign = xmlStrEqual(lasso_node_get_child_content(provider->metadata, "AuthnRequestsSigned", NULL), "true");
  
  /* export request depending on the request ProtocolProfile */
  request_protocolProfile = lasso_provider_get_singleSignOnProtocolProfile(provider);
  if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOGet)) {
    /* GET -> query */
    url = lasso_provider_get_singleSignOnServiceUrl(provider);
    if (must_sign) {
      query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(authn)->request,
					 1, LASSO_PROFILE_CONTEXT(authn)->server->private_key);
    }
    else {
      query = lasso_node_export_to_query(LASSO_PROFILE_CONTEXT(authn)->request, 0, NULL);
    }
    /* alloc returned string +2 for the ? and \0 */
    request_msg = (gchar *) g_new(gchar, strlen(url) + strlen(query) + 2);
    g_sprintf(request_msg, "%s?%s", url, query);
    g_free(url);
    g_free(query);
  }
  else if (xmlStrEqual(request_protocolProfile, lassoLibProtocolProfileSSOPost)) {
    /* POST -> formular */
    printf("TODO - export the AuthnRequest in a formular\n");
  }
  
  return (request_msg);
}

static void
lasso_authentication_process_request(LassoAuthentication *authn,
				     gchar               *request_msg)
{
  LassoProvider *sp;
  gboolean  must_verify_signature, signature_status;

  /* rebuild request */
  switch (authn->request_method) {
  case lassoProfileContextMethodGet:
    LASSO_PROFILE_CONTEXT(authn)->request = LASSO_NODE(lasso_authn_request_new_from_query(request_msg));
    break;
  case lassoProfileContextMethodPost:
    /* request_msg is a LibAuthnRequest send by method POST */
    printf("TODO - lasso_authentication_process_authnRequest() - implement the parsing of the post request\n");
    break;
  case lassoProfileContextMethodSoap:
    /* TODO request_msg is a SamlpRequest -> get SamlpResponse in user part */
    //LASSO_PROFILE_CONTEXT(authn)->response = ;
    return;
    break;
  }
  printf("%s\n", lasso_node_export(LASSO_PROFILE_CONTEXT(authn)->request));

  authn->protocolProfile = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request,
							"ProtocolProfile", NULL);
  if (authn->protocolProfile == NULL) {
    authn->protocolProfile = g_strdup(lassoLibProtocolProfileArtifact);
  }

  LASSO_PROFILE_CONTEXT(authn)->remote_providerID = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request,
										 "ProviderID", NULL);
  sp = lasso_server_get_provider(LASSO_PROFILE_CONTEXT(authn)->server,
				 LASSO_PROFILE_CONTEXT(authn)->remote_providerID);
  must_verify_signature = xmlStrEqual(lasso_node_get_child_content(sp->metadata, "AuthnRequestsSigned", NULL), "true");

  /* build response */
  if (xmlStrEqual(authn->protocolProfile, lassoLibProtocolProfilePost)) {
    /* create LibAuthnResponse */
    LASSO_PROFILE_CONTEXT(authn)->response = lasso_authn_response_new(LASSO_PROFILE_CONTEXT(authn)->local_providerID,
								      LASSO_PROFILE_CONTEXT(authn)->request);
  }
  else if (xmlStrEqual(authn->protocolProfile, lassoLibProtocolProfileArtifact)) {
    /* create SamlpResponse */
    LASSO_PROFILE_CONTEXT(authn)->response = lasso_response_new();
  }

  /* verify signature */
  if (must_verify_signature) {
    switch (authn->request_method) {
    case lassoProfileContextMethodGet:
      signature_status = lasso_query_verify_signature(request_msg,
						      sp->public_key,
						      LASSO_PROFILE_CONTEXT(authn)->server->private_key);
      break;
    case lassoProfileContextMethodPost:
      // TODO use lasso_node_verify_signature
      break;
    }
    
    /* Modify StatusCode if signature is not OK */
    if (signature_status == 0 || signature_status == 2) {
      switch (signature_status) {
      case 0: // Invalid Signature
	lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
						  lassoLibStatusCodeInvalidSignature);
	break;
      case 2: // Unsigned AuthnRequest
	lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
						  lassoLibStatusCodeUnsignedAuthnRequest);
	break;
      }
    }
  }
}

gboolean
lasso_authentication_must_authenticate(LassoAuthentication *authn,
				       gboolean             is_user_authenticated)
{
  gboolean  must_authenticate = TRUE;
  gboolean  isPassive = TRUE;
  gboolean  forceAuthn = FALSE;

  /* verify if the user must be authenticated or not */
  if (xmlStrEqual(lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request, "IsPassive", NULL), "false")) {
    isPassive = FALSE;
  }

  if (xmlStrEqual(lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request, "ForceAuthn", NULL), "true")) {
    forceAuthn = TRUE;
  }

  /* complex test to authentication process */
  if ((forceAuthn == TRUE || is_user_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
  else if (is_user_authenticated == FALSE && isPassive == TRUE) {
    lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
					      lassoLibStatusCodeNoPassive);
    must_authenticate = FALSE;
  }

  return (must_authenticate);
}

gchar *
lasso_authentication_build_response_msg(LassoAuthentication *authn,
					gint                 authentication_result,
					const gchar         *authenticationMethod,
					const gchar         *reauthenticateOnOrAfter)
{
  LassoUser *user;
  xmlChar   *str, *nameIDPolicy, *protocolProfile;
  LassoNode *assertion, *authentication_statement, *idpProvidedNameIdentifier;
  
  LassoIdentity *identity;

  switch (authn->request_method) {
  case lassoProfileContextMethodGet:
  case lassoProfileContextMethodPost:
    /* federation */
    /* verify if a user context exists else create it */
    if (LASSO_PROFILE_CONTEXT(authn)->user == NULL) {
      LASSO_PROFILE_CONTEXT(authn)->user = lasso_user_new();
    }
    identity = lasso_user_find_identity(LASSO_PROFILE_CONTEXT(authn)->user,
					LASSO_PROFILE_CONTEXT(authn)->remote_providerID);
    nameIDPolicy = lasso_node_get_child_content(LASSO_PROFILE_CONTEXT(authn)->request,
						"NameIDPolicy", NULL);
    printf("NameIDPolicy %s\n", nameIDPolicy);
    if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeNone)) {
      if (identity == NULL) {
      lasso_profile_context_set_response_status(LASSO_PROFILE_CONTEXT(authn),
						lassoLibStatusCodeFederationDoesNotExist);
      }
    }
    else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)) {
      printf("DEBUG - NameIDPolicy is federated\n");
      if (identity == NULL) {
	identity = lasso_identity_new(LASSO_PROFILE_CONTEXT(authn)->remote_providerID);
	idpProvidedNameIdentifier = LASSO_NODE(lasso_lib_idp_provided_name_identifier_new(lasso_build_unique_id(32)));
	lasso_identity_set_local_name_identifier(identity, idpProvidedNameIdentifier);
      }
    }
    else if (xmlStrEqual(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)) {
      
    }

    /* fill the response with the assertion */
    if (identity != NULL && authentication_result == 1) {
      printf("DEBUG - an identity found, so build an assertion\n");
      assertion = lasso_assertion_new(LASSO_PROFILE_CONTEXT(authn)->local_providerID,
				      lasso_node_get_attr_value(LASSO_NODE(LASSO_PROFILE_CONTEXT(authn)->request), "RequestID"));
      authentication_statement = lasso_authentication_statement_new(authenticationMethod,
								    reauthenticateOnOrAfter,
								    identity->remote_nameIdentifier,
								    identity->local_nameIdentifier);
      lasso_saml_assertion_add_authenticationStatement(assertion,
      						       authentication_statement);
      lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(LASSO_PROFILE_CONTEXT(authn)->response),
					 assertion);
    }

    if (xmlStrEqual(authn->protocolProfile, lassoLibProtocolProfilePost)) {
      /* return an authnResponse (base64 encoded) */
      //str = lasso_node_export_to_base64(LASSO_PROFILE_CONTEXT(authn)->response);
    }
    else if (xmlStrEqual(protocolProfile, lassoLibProtocolProfileArtifact)) {
      /* return an artifact */
      switch (authn->response_method) {
      case lassoProfileContextMethodRedirect:
	/* return query */
	break;
      case lassoProfileContextMethodPost:
	/* return a formular */
	break;
      }
    }
    break;
  case lassoProfileContextMethodSoap:
    /* return an SamlpResponse (in a dict indexed with artifact in user)*/
    break;
  }
  
  return(str);
}

xmlChar*
lasso_authentication_process_artifact(LassoAuthentication *authn,
				      gchar               *artifact)
{
  LASSO_PROFILE_CONTEXT(authn)->request = lasso_request_new(artifact);
  return (lasso_node_export_to_soap(LASSO_PROFILE_CONTEXT(authn)->request));
}

gboolean
lasso_authentication_process_response(LassoAuthentication *authn,
				      xmlChar             *response_msg)
{
  LassoNode *statusCode, *assertion;
  LassoNode *nameIdentifier, *idpProvidedNameIdentifier;
  char *artifact, *statusCodeValue;

  printf("DEBUG - POST response, process the authnResponse\n");
  LASSO_PROFILE_CONTEXT(authn)->response = LASSO_NODE(lasso_authn_response_new_from_export(response_msg, 0));
    
  /* process the assertion */
  assertion = lasso_node_get_child(LASSO_PROFILE_CONTEXT(authn)->response, "Assertion", NULL);
  if (!assertion) {
    /* TODO ??? */
    return (FALSE);
  }
  else {
    /* TODO verify signature , res in authn->signature_status ? */

  }

  return(TRUE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authentication_instance_init(LassoAuthentication *authn)
{
}

static void
lasso_authentication_class_init(LassoAuthenticationClass *class)
{
}

GType lasso_authentication_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthenticationClass),
      NULL,
      NULL,
/*       (GClassInitFunc) lasso_authentication_class_init, */
      NULL,
      NULL,
      NULL,
      sizeof(LassoAuthentication),
      0,
/*       (GInstanceInitFunc) lasso_authentication_instance_init, */
      NULL,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_PROFILE_CONTEXT,
				       "LassoAuthentication",
				       &this_info, 0);
  }
  return this_type;
}

LassoProfileContext*
lasso_authentication_new(LassoServer *server,
			 LassoUser   *user,
			 gchar       *local_providerID,
			 gchar       *remote_providerID,
			 gchar       *request_msg,
			 gint         request_method,
			 gchar       *response_msg,
			 gint         response_method)
{
  g_return_val_if_fail(local_providerID != NULL, NULL);
  g_return_val_if_fail(remote_providerID != NULL, NULL);

  LassoProfileContext *authn;

  authn = LASSO_PROFILE_CONTEXT(g_object_new(LASSO_TYPE_AUTHENTICATION,
					     "server", server,
					     "user", user,
					     "local_providerID", local_providerID,
					     "remote_providerID", remote_providerID,
					     NULL));

  LASSO_AUTHENTICATION(authn)->request_method  = request_method;
  LASSO_AUTHENTICATION(authn)->response_method = response_method;

  if (request_msg == NULL && response_msg == NULL) {
    /* build the request object */
    authn->request = lasso_authn_request_new(authn->local_providerID);
  }
  else if (request_msg != NULL) {
    /*
      rebuild request
      create response (LibAuthnResponse or SamlpResponse)
      verify request signature -> modify response status if need
    */
    lasso_authentication_process_request(LASSO_AUTHENTICATION(authn), request_msg);
  }
  else if (response_msg != NULL) {
    lasso_authentication_process_response(authn, response_msg);
  }
  
  return (authn);
}
