#ifndef __LOGOUT_H__
#define __LOGOUT_H__

#include <lasso/lasso.h>

LassoNode *lasso_build_logoutRequest(const xmlChar *providerID,
				     LassoNode     *nameIdentifier,
				     const xmlChar *sessionIndex,
				     const xmlChar *relayState,
				     const xmlChar *consent);

LassoNode *lasso_build_logoutResponse(LassoNode     *request,
				      const xmlChar *providerID,
				      const xmlChar *codeValue,
				      const xmlChar *relayState);

#endif /* __LOGOUT_H__ */
