/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
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

#include <lasso/environs/authn_environ.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

char*
lasso_authn_environ_build_request(LassoAuthnEnviron *env, char *authnRequestProtocolProfile){
  LassoEnviron *e = LASSO_ENVIRON(env);
  LassoNode *node = LASSO_NODE(e->local_provider);
  char *url, *query, *protocolProfile;

  e->request = lasso_authn_request_new(lasso_node_get_attr_value(node, "ProviderID"));
  if(authnRequestProtocolProfile){
       lasso_lib_authn_request_set_protocolProfile(e->request, authnRequestProtocolProfile);
  }

  /* get the url and protocol profile */
  url = lasso_node_get_child_content(node, "SingleSignOnServiceUrl", NULL);
  g_return_val_if_fail (url, NULL);
  protocolProfile = lasso_node_get_child_content(node, "SingleSignOnProtocolProfile", NULL);
  g_return_val_if_fail (protocolProfile, NULL);

  /* get or post ? */
  if(strcmp(protocolProfile, lassoLibProtocolProfileSSOGet)==0){
       printf("AuthnRequest Redirect method ...\n");
       return build_request_url(e, url, query, lassoLibProtocolProfileSSOGet);
  }
  else if(strcmp(protocolProfile, lassoLibProtocolProfileSSOPost)==0){
       printf("AuthnRequest POST method ...\n");
       return build_request_url(e, url, lassoLibProtocolProfileSSOPost);
  }
  else
       printf("No method ...\n");

  return(NULL);
}

gboolean lasso_authn_environ_process_request_from_query(LassoAuthnEnviron *env,
							char *query,
							int isAuthenticated){
     LassoEnviron *e = LASSO_ENVIRON(env);
     LassoNode *node = LASSO_NODE(e->local_provider);
     char *protocolProfile, *providerId;

     protocolProfile = lasso_authn_request_get_protocolProfile(query);
     if(strcmp(protocolProfile, lassoLibProtocolProfileArtifact)==0){
	  printf("artifact ...\n");
     }
     else if(strcmp(protocolProfile, lassoLibProtocolProfilePost)==0){
	  printf("post ...\n");
	  providerId = lasso_node_get_attr_value(node, "ProviderID");
	  e->response = lasso_authn_response_new_from_request_query(query, providerId);
	  return lasso_authn_response_must_authenticate(e->response, isAuthenticated);
     }
}

char *lasso_authn_environ_dump_response(LassoAuthnEnviron *env){
     LassoEnviron *e = LASSO_ENVIRON(env);
     char *dump;

     dump = lasso_node_dump(e->response, "utf-8", 1);

     return(dump);
}

char *lasso_environ_process_authentication(LassoAuthnEnviron *env, gboolean isAuthenticated){
     LassoEnviron *e = LASSO_ENVIRON(env);
     LassoNode *response, *assertion, *statement;

     response = e->response;

     
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_environ_instance_init(LassoAuthnEnviron *env)
{
}

static void
lasso_authn_environ_class_init(LassoAuthnEnvironClass *klass)
{
}

GType lasso_authn_environ_get_type()
{
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnEnvironClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_environ_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnEnviron),
      0,
      (GInstanceInitFunc) lasso_authn_environ_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_ENVIRON,
				       "LassoAuthnEnviron",
				       &this_info, 0);
  }
  return this_type;
}

LassoAuthnEnviron* lasso_authn_environ_new(gchar *metadata,
					   gchar *public_key,
					   gchar *private_key,
					   gchar *certificate)
{
  LassoAuthnEnviron *authn;
  LassoEnviron      *e;
  LassoNode         *local_provider;

  authn = g_object_new(LASSO_TYPE_AUTHN_ENVIRON, NULL);
  e = LASSO_ENVIRON(authn);

  local_provider = lasso_provider_new(metadata);
  if(public_key)
       lasso_provider_set_public_key(LASSO_PROVIDER(local_provider), public_key);
  if(private_key)
       lasso_provider_set_private_key(LASSO_PROVIDER(local_provider), private_key);
  if(certificate)
       lasso_provider_set_certificate(LASSO_PROVIDER(local_provider), certificate);
  e->local_provider = local_provider;

  return(authn);
}
