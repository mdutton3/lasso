#include <lasso/protocols/register_name_identifier.h>

xmlChar *lasso_build_url_encoded_message_registerNameIdentifierRequest(LassoNode *request)
{

}

LassoNode *lasso_build_registerNameIdentifierRequest(const char *metadata,
													 LassoNode  *idpProvidedNameIdentifer,
													 LassoNode  *spProvidedNameIdentifier,
													 LassoNode  *oldProvidedNameIdentifier,
													 const char *relayState)
{
	 LassoNode *request;

	 request = lasso_lib_register_name_identifier_request_new();

	 lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
												(const xmlChar *)lasso_build_unique_id(32));
	 lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
												   lassoLibMinorVersion);
	 lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
													lasso_get_current_time());
	 lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
												   lassoLibMajorVersion);

	 lasso_lib_register_name_identifier_request_set_providerID(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
																	request),
															   "badproviderid.com"); // FIXME

	 lasso_lib_register_name_identifier_request_set_idp_provided_name_identifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request), idpProvidedNameIdentifer);

	 lasso_lib_register_name_identifier_request_set_sp_provided_name_identifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request), spProvidedNameIdentifier);

	lasso_lib_register_name_identifier_request_set_old_provided_name_identifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request), oldProvidedNameIdentifier);

	 if(relayState){
		  lasso_lib_register_name_identifier_request_set_relayState(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request), relayState);
	 }

	 return(request);

}

xmlChar *lasso_build_url_encoded_message_registerNameIdentifierResponse(LassoNode *response)
{

}

LassoNode *lasso_build_registerNameIdentifierResponse(LassoNode  *response,
													  const char *statusCodeValue,
													  const char *relayState)
{
	 LassoNode *response, *ss, *ssc;

	 response = lasso_lib_register_name_identifier_response_new();

	 lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
												  (const xmlChar *)lasso_build_unique_id(32));
	 lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
													lassoLibMinorVersion);
	 lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
													lassoLibMajorVersion);
	 lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
													 lasso_get_current_time()); 

	 lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response),
											  "badproviderid.com"); // FIXME

	 ss = lasso_samlp_status_new();
	 ssc = lasso_samlp_status_code_new();
	 lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(ssc), statusCodeValue);
	 lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(ss), LASSO_SAMLP_STATUS_CODE(ssc));
	 lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response), LASSO_SAMLP_STATUS(ss));

	 if(relayState){
		 lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response), relayState); 
	 }

	 return(response);
}
