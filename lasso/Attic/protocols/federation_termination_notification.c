#include <lasso/protocols/federation_termination_notification.h>

xmlChar *lasso_build_url_encoded_message_federationTerminationNotification(LassoNode *request)
{

}

LassoNode *lasso_build_federationTerminationNotification(const char *metadata,
														 LassoNode  *nameIdentifier,
														 const char *consent)
{
	 LassoNode *notification;

	 notification = lasso_lib_federation_termination_notification_new();

	 lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
												(const xmlChar *)lasso_build_unique_id(32));
	 lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification), 
												   lassoLibMinorVersion);
	 lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
													lasso_get_current_time());
	 lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification),
												   lassoLibMajorVersion);

	 lasso_lib_federation_termination_notification_set_providerID(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), "badproviderid.com"); // FIXME

	 lasso_lib_federation_termination_notification_set_nameIdentifier(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), nameIdentifier);

	 if(consent){
		  lasso_lib_federation_termination_notification_set_consent(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), consent);
	 }

	 return(notification);
}
