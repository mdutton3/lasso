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

char *lasso_session_environ_build_authnRequest(LassoSessionEnviron *session,
					       const char         *responseProtocolProfile,
					       gboolean            isPassive,
					       gboolean            forceAuthn,
					       const char         *nameIDPolicy){
     LassoProvider *provider;
     char *str, *requestProtocolProfile;

     char *url, *query;
     int url_len, query_len;

     //LassoEnviron *environ = LASSO_ENVIRON(session);

     provider = lasso_server_environ_get_provider(session->server, session->local_providerID);
     if(!provider)
	  return(NULL);
     
     /* build the request object */
     session->request = LASSO_NODE(lasso_authn_request_new(session->local_providerID));
     if(responseProtocolProfile!=NULL)
	  lasso_lib_authn_request_set_protocolProfile(session->request, responseProtocolProfile);

     if(nameIDPolicy!=NULL)
	  lasso_lib_authn_request_set_nameIDPolicy(session->request, nameIDPolicy);

     lasso_lib_authn_request_set_isPassive(session->request, isPassive);
     lasso_lib_authn_request_set_forceAuthn(session->request, forceAuthn);

     /* export request depending on the request protocol profile */
     str = NULL;
     requestProtocolProfile = lasso_provider_get_singleSignOnProtocolProfile(provider);
     if(!strcmp(requestProtocolProfile, lassoLibProtocolProfileSSOGet)){
	  url = lasso_provider_get_singleSignOnServiceUrl(provider);
	  url_len = strlen(url);

	  query = lasso_node_export_to_query(session->request, 1, NULL);
	  query_len = strlen(query);

	  str = (char *)malloc(url_len+query_len+2); // +2 for the ? character and the end line character
	  sprintf(str, "%s?%s", url, query);

	  session->request_protocol_profile = lasso_protocol_profile_type_get;
     }
     else if(!strcmp(requestProtocolProfile, lassoLibProtocolProfileSSOPost)){
	  printf("TODO - export the AuthnRequest in a formular\n");
     }

     return(str);
}

gboolean lasso_session_environ_process_assertion(LassoSessionEnviron *session, char *str){
     LassoNode *statusCode, *assertion;
     LassoNode *nameIdentifier, *idpProvidedNameIdentifier;
     char *artifact, *statusCodeValue;

     LassoEnviron *environ = LASSO_ENVIRON(session);

     artifact = strstr(str, "SAMLArt");
     if(artifact){
	  printf("TODO - lasso_session_environ_process_assertion() - process artifact\n");
     }
     else{
	  printf("DEBUG - POST response, process the authnResponse\n");
	  session->response = LASSO_NODE(lasso_authn_response_new_from_export(str, 0));

	  /* process the status code value */
	  statusCode = lasso_node_get_child(session->response, "StatusCode", NULL);
	  statusCodeValue = lasso_node_get_attr_value(statusCode, "Value");
	  if(strcmp(statusCodeValue, lassoSamlStatusCodeSuccess))
	       return(FALSE);
	  
	  /* process the assertion */
	  assertion = lasso_node_get_child(session->response, "Assertion", NULL);
	  if(!assertion)
	       return(FALSE);

	  /* set the name identifiers */
	  nameIdentifier = lasso_node_get_child(assertion, "NameIdentifier", NULL);
	  printf("name identifier %s(%s)\n", lasso_node_get_content(nameIdentifier), lasso_node_export(nameIdentifier));

	  idpProvidedNameIdentifier = lasso_node_get_child(assertion, "IDPProvidedNameIdentifier", NULL);
	  

     }

     return(FALSE);
}

gboolean lasso_session_environ_process_authnRequest(LassoSessionEnviron *session,
						    char *str_request,
						    int protocol_profile_type,
						    gboolean has_cookie){
     gboolean must_authenticate = TRUE;
     char    *response_protocol_profile;
     char    *content;
     gboolean isPassive = TRUE;
     gboolean forceAuthn = FALSE;

     LassoEnviron *environ = LASSO_ENVIRON(session);

     printf("plop, process AuthnRequest\n");

     /* get the protocol profile */
     if(protocol_profile_type==lasso_protocol_profile_type_get){
	  session->request = LASSO_NODE(lasso_authn_request_new_from_query(str_request));
     }
     else if(protocol_profile_type==lasso_protocol_profile_type_post){
	  printf("TODO - lasso_session_environ_process_authnRequest() - implement the parsing of the post request\n");
     }
     else{
	  printf("ERROR - lasso_session_environ_process_authnRequest() - Unknown protocol profile\n");
     }

     /* Verify the signature */
     printf("TODO - verify the signature\n");

     /* set the peer ProviderID from the request */
     content = lasso_node_get_child_content(session->request, "ProviderID", NULL);
     session->peer_providerID = (char *)malloc(strlen(content)+1);
     sprintf(session->peer_providerID, "%s", content);
     printf("request from %s\n", session->peer_providerID);

     /* response with protocol profile */
     response_protocol_profile = lasso_node_get_child_content(session->request, "ProtocolProfile", NULL);
     if(!response_protocol_profile || !strcmp(response_protocol_profile, lassoLibProtocolProfileArtifact)){
	  session->response_protocol_profile = lasso_protocol_profile_type_artifact;
	  printf("TODO - lasso_session_environ_process_authnRequest() - implement the artifact response\n");
     }
     else if(!strcmp(response_protocol_profile, lassoLibProtocolProfilePost)){
	  session->response_protocol_profile = lasso_protocol_profile_type_post;
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

     /* complex test to authentication process */
     if((forceAuthn == TRUE || has_cookie == FALSE) && isPassive == FALSE){
	  must_authenticate = TRUE;
     }
     else if(has_cookie == FALSE && isPassive == TRUE){
	  printf("TODO - lasso_session_session_process_authnRequest() - implement the generic setting of the status code value\n");
	  must_authenticate = FALSE;
     }

     return(must_authenticate);
}

char *lasso_session_environ_process_authentication(LassoSessionEnviron *session,
						   gboolean             isAuthenticated,
						   const char          *authentication_method){
     LassoUserEnviron *user;
     char             *str, *nameIDPolicy;
     LassoNode        *assertion, *authentication_statement, *idpProvidedNameIdentifier;

     LassoIdentity *identity;

     /* process the federation policy */
     /* TODO : implement a get identity */

     printf("process authentication\n");
     /* verify if a user environ exists */
     if(!session->user){
	  session->user = lasso_user_environ_new();
     }

     identity = lasso_user_environ_find_identity(session->user, session->peer_providerID);
     nameIDPolicy = lasso_node_get_child_content(session->request, "NameIDPolicy", NULL);
     printf("NameIDPolicy %s\n", nameIDPolicy);
     if(!nameIDPolicy || !strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeNone)){
	  if(!identity){
	       printf("TODO - set the StatusCode value with lassoLibStatusCodeFederationDoesNotExist\n");
	  }
     }
     else if(!strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeFederated)){
	  printf("DEBUG - NameIDPolicy is federated\n");
	  if(!identity){
	       identity = lasso_identity_new(session->peer_providerID);
	       idpProvidedNameIdentifier = LASSO_NODE(lasso_lib_idp_provided_name_identifier_new(lasso_build_unique_id(32)));
	       lasso_identity_set_local_name_identifier(identity, idpProvidedNameIdentifier);
	  }
     }
     else if(!strcmp(nameIDPolicy, lassoLibNameIDPolicyTypeOneTime)){
	  
     }

     /* fill the response with the assertion */
     if(identity){
	  printf("DEBUG - an identity found, so build an assertion\n");
	  //assertion = lasso_assertion_new(session->local_providerID, lasso_node_get_attr_value(LASSO_NODE(session->request),
	  //									       "RequestID"));
	  //authentication_statement = lasso_authentication_statement_new(authentication_method,
	  //							"TODO",
	  //							nameIdentifier,
	  //							"TODO",
	  //							"TODO",
	  //							idpProvidedNameIdentifier,
	  //							"TODO",
	  //							"TODO");
	  //lasso_saml_assertion_add_authenticationStatement(assertion,
	  //					   authentication_statement);
	  //lasso_samlp_response_add_assertion(session->response, assertion);
     }

     /* return a response message */
     str = NULL;
     if(session->response_protocol_profile==lasso_protocol_profile_type_post){
	  printf("DEBUG - return a post message\n");
	  str = lasso_node_export_to_base64(session->response);
     }
     else if(session->response_protocol_profile==lasso_protocol_profile_type_artifact){
	  printf("DEBUG - return a artifact message\n");
     }
     else{
	  printf("DEBUG - unknown response protocol profile\n");
     }

     return(str);
}

int lasso_session_environ_set_local_providerID(LassoSessionEnviron *session, char *providerID){
     if(session->local_providerID)
	  free(session->local_providerID);
     session->local_providerID = (char *)malloc(strlen(providerID)+1);
     strcpy(session->local_providerID, providerID);

     return(1);
}

int lasso_session_environ_set_peer_providerID(LassoSessionEnviron *session, char *providerID){
     if(session->peer_providerID)
	  free(session->peer_providerID);
     session->peer_providerID = (char *)malloc(strlen(providerID)+1);
     strcpy(session->peer_providerID, providerID);

     return(1);
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_session_environ_instance_init(LassoSessionEnviron *session){
  session->user = NULL;
  session->message = NULL;
  session->request  = NULL;
  session->response = NULL;
  session->local_providerID = NULL;
  session->peer_providerID = NULL;
  session->request_protocol_profile  = 0;
  session->response_protocol_profile = 0;
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
    
    this_type = g_type_register_static(LASSO_TYPE_ENVIRON,
				       "LassoSessionEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoSessionEnviron*
lasso_session_environ_new(LassoServerEnviron *server,
			  LassoUserEnviron   *user,
			  gchar              *local_providerID,
			  gchar              *peer_providerID)
{
  /* load the ProviderID name or a reference to the provider ? */
  g_return_val_if_fail(local_providerID != NULL, NULL);
  g_return_val_if_fail(peer_providerID != NULL, NULL);

  LassoSessionEnviron *session;

  session = g_object_new(LASSO_TYPE_SESSION_ENVIRON, NULL);

  session->server = server;

  if (user) {
    session->user = user;
  }

  lasso_session_environ_set_local_providerID(session, local_providerID);
  lasso_session_environ_set_peer_providerID(session, peer_providerID);

  return (session);
}
