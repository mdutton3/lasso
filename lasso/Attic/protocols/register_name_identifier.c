#include <lasso/protocols/register_name_identifier.h>

static LassoNode *
lasso_register_name_identifier_request_build_full(const xmlChar *requestID,
						  const xmlChar *majorVersion,
						  const xmlChar *minorVersion,
						  const xmlChar *issueInstant,
						  const xmlChar *providerID,
						  const xmlChar *idpNameIdentifier,
						  const xmlChar *idpNameQualifier,
						  const xmlChar *idpFormat,
						  const xmlChar *spNameIdentifier,
						  const xmlChar *spNameQualifier,
						  const xmlChar *spFormat,
						  const xmlChar *oldNameIdentifier,
						  const xmlChar *oldNameQualifier,
						  const xmlChar *oldFormat,
						  const xmlChar *relayState)
{
  LassoNode *request, *idpIdentifierNode, *spIdentifierNode, *oldIdentifierNode;
  
  request = lasso_lib_register_name_identifier_request_new();
  
  if (requestID != NULL) {
    lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					       requestID);	 
  }
  else {
    lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					       (const xmlChar *)lasso_build_unique_id(32));
  }
  
  if (majorVersion != NULL) {
    lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  majorVersion);
    
  }
  else {
    lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  lassoLibMajorVersion);
  }

  if (minorVersion != NULL){
    lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						  minorVersion);	 
  }
  else {
    lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						  lassoLibMinorVersion);
  }

  if (issueInstant != NULL){
    lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						   issueInstant);	 
  }
  else{
    lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						   lasso_get_current_time());
  }
  
  lasso_lib_register_name_identifier_request_set_providerID(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
							    providerID);
 
  idpIdentifierNode = lasso_lib_idp_provided_name_identifier_new(idpNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(idpIdentifierNode), idpNameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(idpIdentifierNode), idpFormat);
  lasso_lib_register_name_identifier_request_set_idp_provided_name_identifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									      idpIdentifierNode);
  
  spIdentifierNode = lasso_lib_sp_provided_name_identifier_new(spNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(spIdentifierNode), spNameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(spIdentifierNode), spFormat);
  lasso_lib_register_name_identifier_request_set_sp_provided_name_identifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									     spIdentifierNode);
  
  oldIdentifierNode = lasso_lib_old_provided_name_identifier_new(oldNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(oldIdentifierNode), oldNameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(oldIdentifierNode), oldFormat);
  lasso_lib_register_name_identifier_request_set_old_provided_name_identifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									      oldIdentifierNode);
	 
  if (relayState != NULL) {
    lasso_lib_register_name_identifier_request_set_relayState(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
							      relayState);
  }
  
  return (request);
}

lassoRegisterNameIdentifierRequest *
lasso_register_name_identifier_request_create(const xmlChar *providerID,
					      const xmlChar *idpNameIdentifier,
					      const xmlChar *idpNameQualifier,
					      const xmlChar *idpFormat,
					      const xmlChar *spNameIdentifier,
					      const xmlChar *spNameQualifier,
					      const xmlChar *spFormat,
					      const xmlChar *oldNameIdentifier,
					      const xmlChar *oldNameQualifier,
					      const xmlChar *oldFormat,
					      const xmlChar *relayState)
{
  lassoRegisterNameIdentifierRequest *lareq;

  lareq = g_malloc(sizeof(lassoRegisterNameIdentifierRequest));
  lareq->node = lasso_register_name_identifier_request_build_full(NULL,
								  NULL,
								  NULL,
								  NULL,
								  providerID,
								  idpNameIdentifier,
								  idpNameQualifier,
								  idpFormat,
								  spNameIdentifier,
								  spNameQualifier,
								  spFormat,
								  oldNameIdentifier,
								  oldNameQualifier,
								  oldFormat,
								  relayState);
  return (lareq);
}

static LassoNode *
lasso_registerNameIdentifierResponse_build_full(const xmlChar *responseID,
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
  
  response = lasso_lib_register_name_identifier_response_new();
  
  if (responseID != NULL) {
    lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 responseID);
  }
  else {
    lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 (const xmlChar *)lasso_build_unique_id(32));
  }
  
  if (majorVersion != NULL) {
    lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   majorVersion);
  }
  else {
    lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lassoLibMajorVersion);
  }
  
  if (minorVersion != NULL) {
    lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   minorVersion);
  }
  else {
    lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lassoLibMinorVersion);
  }
  
  if (issueInstant != NULL) {
    lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						    issueInstant);
  }
  else {
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
  
  if (relayState != NULL) {
    lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response), relayState); 
  }
  
  return (response);
}
