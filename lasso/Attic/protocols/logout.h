#ifndef __LOGOUT_H__
#define __LOGOUT_H__

#include <lasso/lasso.h>

xmlChar *lasso_build_url_encoded_message_logoutRequest(LassoNode *);

LassoNode *lasso_build_logoutRequest(const char *metadata,
									 LassoNode  *nameIdentifier,
									 const char *sessionIndex,
									 const char *relayState,
									 const char *consent);

xmlChar *lasso_build_url_encoded_message_logoutResponse(LassoNode *);

LassoNode *lasso_build_logoutResponse(LassoNode *request,
									  const char*codeValue,
									  const char*relayState);

#endif /* __LOGOUT_H__ */
