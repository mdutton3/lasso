#include <lasso/protocols/single_sign_on_and_federation.h>

xmlChar *lasso_build_url_encoded_message_authnRequest(LassoNode *request)
{

	 xmlChar *authority = "https://idpprovider.com";
	 xmlChar *query;

}

LassoNode *lasso_build_authnRequest(const char *providerID,
									const char *nameIDPolicy,
									const char *isPassive,
									const char *forceAuthn,
									const char *assertionConsumerServiceID,
									const char **authnContextClassRefs,
									const char **authnContextStatementRefs,
									const char *authnContextComparison,
									const char *relayState,
									const char *proxyCount,
									const char **idpList,
									const char *consent)
{
	 LassoNode  *request;

	 // build AuthnRequest class
	 request = lasso_lib_authn_request_new();

	 lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
										  (const xmlChar *)lasso_build_unique_id(32));
	 lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
												   lassoLibMinorVersion);
	 lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
													lasso_get_current_time());
	 lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
												   lassoLibMajorVersion);

	 lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request),
											providerID);

	 if(nameIDPolicy){
		  lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(request), nameIDPolicy);
	 }

	 if(isPassive){
		  lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(request), isPassive);
	 }

	 if(forceAuthn){
		  lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(request), forceAuthn);
	 }

	 if(assertionConsumerServiceID){
		  lasso_lib_authn_request_set_assertionConsumerServiceID(LASSO_LIB_AUTHN_REQUEST(request),
																 assertionConsumerServiceID);
	 }

	 if(relayState!=NULL){
		  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request), relayState);
	 }

	 if(consent!=NULL){
		  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request), consent);
	 }

	 return(request);
}
