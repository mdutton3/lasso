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

#include <lasso/environs/session_environ.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoIdentity *lasso_session_environ_assertion_consume(LassoSessionEnviron *session){
     LassoIdentity *identity;
     LassoNode *statusCode;
     char *statusCodeValue, *nameIdentifier, *idpProvidedNameIdentifier;

     statusCode = lasso_node_get_child(session->response, "StatusCode", NULL);
     statusCodeValue = lasso_node_get_attr_value(statusCode, "Value");
     printf("DEBUG - StatusCode Value %s\n", statusCodeValue);
     if(!strcmp(statusCodeValue, lassoSamlStatusCodeSuccess)){
	  printf("authentication is ok\n");

	  nameIdentifier = lasso_node_get_child_content(session->response, "NameIdentifier", NULL);
	  idpProvidedNameIdentifier = lasso_node_get_child_content(session->response, "IDPProvidedNameIdentifier", NULL);

	  identity = lasso_identity_search_by_alias(session->userEnviron, nameIdentifier);
	  if(!identity){
	       identity = lasso_user_environ_search_by_name(session->userEnviron, idpProvidedNameIdentifier);
	  }
	  if(!identity){
	       printf("No identity for %s, new identity at %s\n", idpProvidedNameIdentifier, session->local_providerID);
	       identity = lasso_user_environ_new_from_name(session->peer_providerID, idpProvidedNameIdentifier);
	  }
	  return(identity);
     }

     return(NULL);
}

char *lasso_session_environ_build_authnRequest(LassoSessionEnviron *session,
					       const char *responseProtocolProfile,
					       gboolean isPassive,
					       gboolean forceAuthn,
					       const char *nameIDPolicy){
     LassoProvider *provider;
     char *str, *requestProtocolProfile;

     printf("DEBUG - Build authentication ...\n");

     provider = lasso_server_environ_get_provider(session->serverEnviron, session->local_providerID);

     /* build the request object */
     session->request = LASSO_NODE(lasso_authn_request_new(session->local_providerID));
     if(responseProtocolProfile!=NULL)
	  lasso_lib_authn_request_set_protocolProfile(session->request, responseProtocolProfile);

     if(nameIDPolicy!=NULL)
	  lasso_lib_authn_request_set_nameIDPolicy(session->request, nameIDPolicy);

     lasso_lib_authn_request_set_isPassive(session->request, isPassive);
     lasso_lib_authn_request_set_forceAuthn(session->request, forceAuthn);

     /* export request depending on the request protocol profile */
     requestProtocolProfile = lasso_node_get_child_content(LASSO_NODE(provider), "SingleSignOnProtocolProfile", NULL);
     if(!strcmp(requestProtocolProfile, lassoLibProtocolProfileSSOGet)){
	  char *url, *query;
	  int url_len, query_len;

	  url = lasso_node_get_child_content(LASSO_NODE(provider), "SingleSignOnServiceUrl", NULL);
	  url_len = strlen(url);

	  query = lasso_node_export_to_query(session->request, 1, NULL);
	  query_len = strlen(query);

	  str = (char *)malloc(url_len+query_len+1); // +1 for the ? character
	  sprintf(str, "%s?%s", url, query);

	  session->request_protocol_profile_type = protocol_profile_type_get;
	  
     }
     else if(!strcmp(requestProtocolProfile, lassoLibProtocolProfileSSOPost)){
     }
     else{
	  return(NULL);
     }
     //printf("data : %s\n", str);

     return(str);
}

gboolean lasso_session_environ_process_authnRequest(LassoSessionEnviron *session,
						    char *str_request,
						    int protocol_profile_type,
						    gboolean has_cookie){
     gboolean must_authenticate = TRUE;
     char *response_protocolProfile;
     char *content;
     gboolean isPassive = TRUE;
     gboolean forceAuthn = FALSE;

     LassoNode *statusCode;

     printf("DEBUG - Process authentication ...\n");

     session->request = NULL;
     session->response = NULL;

     if(protocol_profile_type==protocol_profile_type_get){
	  printf("DEBUG - rebuild AuthnRequest from query\n");
	  session->request = LASSO_NODE(lasso_authn_request_new_from_query(str_request));
     }
     else{
	  printf("DEBUG - unknown protocol profile\n");
	  return(FALSE);
     }

     /* response with protocol profile */
     response_protocolProfile = lasso_node_get_child_content(session->request, "ProtocolProfile", NULL);
     if(!response_protocolProfile || !strcmp(response_protocolProfile, lassoLibProtocolProfileArtifact)){
	  printf("DEBUG - response with protocol artifact\n");
	  session->response = NULL;
	  session->response_protocol_profile_type = protocol_profile_type_artifact;
     }
     else if(!strcmp(response_protocolProfile, lassoLibProtocolProfilePost)){
	  printf("DEBUG - response with post profile\n");
	  session->response_protocol_profile_type = protocol_profile_type_post;
	  session->response = LASSO_NODE(lasso_authn_response_new(session->local_providerID, session->request));
     }

     /* verify if the user must be authenticated or not */
     content = lasso_node_get_child_content(session->request, "IsPassive", NULL);
     if(content && !strcmp(content, "false")){
	  isPassive = FALSE;
     }

     content = lasso_node_get_child_content(session->request, "ForceAuthn", NULL);
     if(content && !strcmp(content, "true")){
	  forceAuthn = TRUE;
     }

     if((forceAuthn == TRUE || has_cookie == FALSE) && isPassive == FALSE){
	  must_authenticate = TRUE;
     }
     else if(has_cookie == FALSE && isPassive == TRUE){
	  lasso_authn_response_set_status(session->response, lassoLibStatusCodeNoPassive);
     }

     return(must_authenticate);
}

char *lasso_session_environ_process_authentication(LassoSessionEnviron *session,
						   gboolean isAuthenticated,
						   const char *authentication_method){
     LassoUserEnviron *user;
     LassoIdentity    *identity;
     char             *str, *nameIDPolicy, *nameIdentifier, *idpProvidedNameIdentifier;
     LassoNode        *assertion, *authentication_statement;

     printf("DEBUG - Process authentication ...\n");

     /* process the federation policy */
     identity = lasso_user_environ_search_identity(session->userEnviron, session->peer_providerID);
     nameIDPolicy = lasso_node_get_child_content(session->request, "NameIDPolicy", NULL);
     if(!nameIDPolicy || !strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeNone)){
	  printf("NameIDPolicy is none\n");
	  if(!identity){
	       printf("TODO - set the StatusCode value with lassoLibStatusCodeFederationDoesNotExist\n");
	  }
     }
     else if(!strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)){
	  printf("NameIDPolicy is federated\n");
	  if(!identity)
	       identity = lasso_user_environ_new_identity(session->userEnviron, session->peer_providerID);

     }
     else if(!strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)){

     }

     /* fill the response with the assertion */
     if(identity){
	  idpProvidedNameIdentifier = lasso_identity_get_alias(identity);
	  nameIdentifier = lasso_identity_get_name(identity);
	  if(!nameIdentifier)
	       nameIdentifier = idpProvidedNameIdentifier;

	  assertion = lasso_assertion_new(session->local_providerID, lasso_node_get_attr_value(LASSO_NODE(session->request),
											       "RequestID"));
	  authentication_statement = lasso_authentication_statement_new(authentication_method,
									"TODO",
									nameIdentifier,
									"TODO",
									"TODO",
									idpProvidedNameIdentifier,
									"TODO",
									"TODO");
	  lasso_saml_assertion_add_authenticationStatement(assertion,
							   authentication_statement);
	  lasso_samlp_response_add_assertion(session->response, assertion);
     }

     /* return a response message */
     if(session->response_protocol_profile_type==protocol_profile_type_post){
	  printf("DEBUG - return a post message\n");
	  str = lasso_node_export_to_base64(session->response);
     }
     else if(session->response_protocol_profile_type==protocol_profile_type_artifact){
	  printf("DEBUG - return a artifact message\n");
     }
     else{
	  printf("DEBUG - unknown response protocol profile\n");
     }

     return(str);
}

void lasso_session_environ_set_local_providerID(LassoSessionEnviron *session, char *providerID){
     if(session->local_providerID)
	  free(session->local_providerID);
     session->local_providerID = (char *)malloc(strlen(providerID)+1);
     strcpy(session->local_providerID, providerID);
}

void lasso_session_environ_set_peer_providerID(LassoSessionEnviron *session, char *providerID){
     if(session->peer_providerID)
	  free(session->peer_providerID);
     session->peer_providerID = (char *)malloc(strlen(providerID)+1);
     strcpy(session->peer_providerID, providerID);
}



/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_session_environ_instance_init(LassoSessionEnviron *session){
    LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(session));
    class->set_name(LASSO_NODE(session), "SessionEnviron");
}

static void
lasso_session_environ_class_init(LassoSessionEnvironClass *klass) {
}

GType lasso_session_environ_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSessionEnvironClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_session_environ_class_init,
      NULL,
      NULL,
      sizeof(LassoSessionEnviron),
      0,
      (GInstanceInitFunc) lasso_session_environ_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSessionEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoSessionEnviron*
lasso_session_environ_new(LassoServerEnviron *server, LassoUserEnviron *user, char *local_providerID, char *peer_providerID)
{
  LassoSessionEnviron *session;

  session = LASSO_SESSION_ENVIRON(g_object_new(LASSO_TYPE_SESSION_ENVIRON, NULL));

  session->serverEnviron = server;
  session->userEnviron = user;
  lasso_session_environ_set_local_providerID(session, local_providerID);
  lasso_session_environ_set_peer_providerID(session, peer_providerID);

  return(session);
}
