/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/protocols/logout.h>

/*****************************************************************************/
/* LogoutRequest                                                             */
/*****************************************************************************/

static LassoNode *
lasso_logout_request_build_full(const char    *requestID,
			       const xmlChar *majorVersion,
			       const xmlChar *minorVersion,
			       const xmlChar *issueInstant,
			       const xmlChar *providerID,
			       xmlChar       *nameIdentifier,
			       const xmlChar *nameQualifier,
			       const xmlChar *format,
			       const xmlChar *sessionIndex,
			       const xmlChar *relayState,
			       const xmlChar *consent)
{
     LassoNode *request, *identifier;

     request = lasso_lib_logout_request_new();

     if(requestID!=NULL){
	  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						     requestID);
     }
     else{
	  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						     (const xmlChar *)lasso_build_unique_id(32));	  
     }

     if(majorVersion!=NULL){
	  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
							majorVersion);	  
     }
     else{
	  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
							lassoLibMajorVersion);
     }

     if(minorVersion!=NULL){
	  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
							minorVersion);	  
     }
     else{
	  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
							lassoLibMinorVersion);
     }

     if(issueInstant!=NULL){
	  lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
							 issueInstant);
     }
     else{
	  lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
							 lasso_get_current_time());
     }

     lasso_lib_logout_request_set_providerID(LASSO_LIB_LOGOUT_REQUEST(request),
					     providerID);

     identifier = lasso_saml_name_identifier_new(nameIdentifier);
     lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier),
						  nameQualifier);
     lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier),
					   format);
     lasso_lib_logout_request_set_nameIdentifier(LASSO_LIB_LOGOUT_REQUEST(request),
						 LASSO_SAML_NAME_IDENTIFIER(identifier));

     if(sessionIndex){
	  lasso_lib_logout_request_set_sessionIndex(LASSO_LIB_LOGOUT_REQUEST(request),
						    sessionIndex);
     }

     if(relayState){
	  lasso_lib_logout_request_set_relayState(LASSO_LIB_LOGOUT_REQUEST(request),
						  relayState);
     }

     if(consent){
	  lasso_lib_logout_request_set_consent(LASSO_LIB_LOGOUT_REQUEST(request),
					       consent);
     }

     return(request);

}

lassoLogoutRequest *
lasso_logout_request_create(const xmlChar *providerID,
			    xmlChar       *nameIdentifier,
			    const xmlChar *nameQualifier,
			    const xmlChar *format,
			    const xmlChar *sessionIndex,
			    const xmlChar *relayState,
			    const xmlChar *consent)
{
     lassoLogoutRequest *lareq;

     lareq = g_malloc(sizeof(lassoLogoutRequest));
     lareq->node = lasso_logout_request_build_full(NULL,
						   NULL,
						   NULL,
						   NULL,
						   providerID,
						   nameIdentifier,
						   nameQualifier,
						   format,
						   sessionIndex,
						   relayState,
						   consent);
     return(lareq);
}


/*****************************************************************************/
/* LogoutResponse                                                            */
/*****************************************************************************/

static LassoNode *
lasso_logout_response_build_full(const xmlChar *responseID,
				 const xmlChar *majorVersion,
				 const xmlChar *minorVersion,
				 const xmlChar *issueInstant,
				 const xmlChar *inResponseTo,
				 const xmlChar *recipient,
				 const xmlChar *providerID,
				 const xmlChar *statusCodeValue,
				 const xmlChar *relayState)
{
	 LassoNode *response, *ss, *ssc;

	 response = lasso_lib_logout_response_new();

	 if(responseID!=NULL){
	      lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							   responseID);
	 }
	 else{
	      lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							   (const xmlChar *)lasso_build_unique_id(32));
	 }

	 if(majorVersion!=NULL){
	      lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							     majorVersion);
	 }
	 else{
	      lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							     lassoLibMajorVersion);
	 }

	 if(minorVersion!=NULL){
	      lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							     minorVersion);
	 }
	 else{
	      lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							     lassoLibMinorVersion);
	 }
	 
	 if(issueInstant!=NULL){
	      lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							      issueInstant);
	 }
	 else{
	      lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							      lasso_get_current_time());
	 }

	 lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
							inResponseTo);

	 lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						     recipient);

	 lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response),
						  providerID);
 
	 ss = lasso_samlp_status_new();
	 ssc = lasso_samlp_status_code_new();
	 lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(ssc), statusCodeValue);
	 lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(ss), LASSO_SAMLP_STATUS_CODE(ssc));
	 lasso_lib_status_response_set_status(LASSO_LIB_STATUS_RESPONSE(response), LASSO_SAMLP_STATUS(ss));

	 if(relayState){
		 lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response),
							  relayState); 
	 }

	 return(response);
}

lassoLogoutResponse *
lasso_logout_response_create(xmlChar       *query,
			     gboolean       verifySignature,
			     const xmlChar *public_key,
			     const xmlChar *private_key,
			     const xmlChar *certificate)
{
     lassoLogoutResponse *lares;
     LassoNode *request = NULL;
     GData     *gd;

     lares = g_malloc(sizeof(lassoLogoutResponse));
     lares->request_query = NULL;
     if(query!=NULL){
	  lares->request_query = query;

	  gd = lasso_query_to_dict(query);
	  if (gd != NULL) {
	       request = lasso_logout_request_build_full(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstance"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIdentifier"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameQualifier"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "Format"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SessionIndex"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0),
							 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0));
	  }
	  g_datalist_clear(&gd);

	  lares->request_node = request;

     }

     return(lares);
}

gint
lasso_logout_response_init(lassoLogoutResponse *lares,
			   const xmlChar       *providerID,
			   const xmlChar       *statusCodeValue,
			   const xmlChar       *relayState)
{
     LassoNode *response;
     xmlChar *inResponseTo, *recipient;

     inResponseTo = xmlNodeGetContent((xmlNodePtr)lasso_node_get_attr(lares->request_node, "RequestID"));
     recipient = lasso_node_get_content(lasso_node_get_child(lares->request_node, "ProviderID"));

     response = lasso_logout_response_build_full(NULL,
						 NULL,
						 NULL,
						 NULL,
						 inResponseTo,
						 recipient,
						 providerID,
						 statusCodeValue,
						 relayState);

     lares->node = response;

     return(1);
}
