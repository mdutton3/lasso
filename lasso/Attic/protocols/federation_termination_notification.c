#include <lasso/protocols/federation_termination_notification.h>

LassoNode *lasso_build_full_federationTerminationNotification(const xmlChar *requestID,
							      const xmlChar *majorVersion,
							      const xmlChar *minorVersion,
							      const xmlChar *issueInstant,
							      const xmlChar *providerID,
							      LassoNode     *nameIdentifier,
							      const xmlChar *consent)
{
	 LassoNode *notification;

	 notification = lasso_lib_federation_termination_notification_new();

	 if(requestID!=NULL){
	      lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
							 requestID);
	 }
	 else{
	      lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
							 (const xmlChar *)lasso_build_unique_id(32));
	 }

	 if(majorVersion!=NULL){
	      lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
							    majorVersion);
	 }
	 else{
	      lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
							    lassoLibMajorVersion);
	 }

	 if(minorVersion!=NULL){
	      lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification), 
							    minorVersion);
	 }
	 else{
	      lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification), 
							    lassoLibMinorVersion);
	 }

	 if(issueInstant!=NULL){
	      lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
							     issueInstant);
	 }
	 else{
	      lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
							     lasso_get_current_time());
	 }

	 lasso_lib_federation_termination_notification_set_providerID(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), providerID);

	 lasso_lib_federation_termination_notification_set_nameIdentifier(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), nameIdentifier);

	 if(consent){
		  lasso_lib_federation_termination_notification_set_consent(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), consent);
	 }

	 return(notification);
}

LassoNode *lasso_build_federationTerminationNotification(const xmlChar *providerID,
							 LassoNode     *nameIdentifier,
							 const xmlChar *consent)
{
     LassoNode *notification;

     notification = lasso_build_full_federationTerminationNotification(NULL,
								       NULL,
								       NULL,
								       NULL,
								       providerID,
								       nameIdentifier,
								       consent);
     return(notification);
}
