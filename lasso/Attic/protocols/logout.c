#include <lasso/protocols/logout.h>

LassoNode *lasso_build_full_logoutRequest(const char    *requestID,
					  const xmlChar *majorVersion,
					  const xmlChar *minorVersion,
					  const xmlChar *issueInstant,
					  const xmlChar *providerID,
					  LassoNode     *nameIdentifier,
					  const xmlChar *sessionIndex,
					  const xmlChar *relayState,
					  const xmlChar *consent)
{
     LassoNode *request;

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
     
     
     lasso_lib_logout_request_set_nameIdentifier(LASSO_LIB_LOGOUT_REQUEST(request),
						 nameIdentifier);

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

}

LassoNode *lasso_build_logoutRequest(const xmlChar *providerID,
				     LassoNode     *nameIdentifier,
				     const xmlChar *sessionIndex,
				     const xmlChar *relayState,
				     const xmlChar *consent)
{
     LassoNode *request;

     request = lasso_build_full_logoutRequest(NULL,
					      NULL,
					      NULL,
					      NULL,
					      providerID,
					      nameIdentifier,
					      sessionIndex,
					      relayState,
					      consent);
     return(request);

}

LassoNode *lasso_build_full_logoutResponse(const xmlChar *responseID,
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
	 lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response), LASSO_SAMLP_STATUS(ss));

	 if(relayState){
		 lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response),
							  relayState); 
	 }

	 return(response);
}

LassoNode *lasso_build_logoutResponse(LassoNode     *request,
				      const xmlChar *providerID,
				      const xmlChar *statusCodeValue,
				      const xmlChar *relayState)
{
     LassoNode *response;

     response = lasso_build_full_logoutResponse(NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						providerID,
						statusCodeValue,
						relayState);
     return(response);
}

