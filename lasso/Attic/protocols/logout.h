#ifndef __LOGOUT_H__
#define __LOGOUT_H__

#include <lasso/lasso.h>

LassoNode *lasso_build_full_logoutRequest(const char    *requestID,
					  const xmlChar *majorVersion,
					  const xmlChar *minorVersion,
					  const xmlChar *issueInstant,
					  const xmlChar *providerID,
					  LassoNode     *nameIdentifier,
					  const xmlChar *sessionIndex,
					  const xmlChar *relayState,
					  const xmlChar *consent);

LassoNode *lasso_build_logoutRequest(const xmlChar *providerID,
				     LassoNode     *nameIdentifier,
				     const xmlChar *sessionIndex,
				     const xmlChar *relayState,
				     const xmlChar *consent);

LassoNode *lasso_build_full_logoutResponse(const xmlChar *responseID,
					   const xmlChar *majorVersion,
					   const xmlChar *minorVersion,
					   const xmlChar *issueInstant,
					   const xmlChar *inResponseTo,
					   const xmlChar *recipient,
					   const xmlChar *providerID,
					   const xmlChar *statusCodeValue,
					   const xmlChar *relayState);

LassoNode *lasso_build_logoutResponse(LassoNode     *request,
				      const xmlChar *providerID,
				      const xmlChar *statusCodeValue,
				      const xmlChar *relayState);

#endif /* __LOGOUT_H__ */
