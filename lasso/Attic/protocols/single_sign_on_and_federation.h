#ifndef SINGLE_SIGN_ON_AND_FEDERATION_H
#define SINGLE_SIGN_ON_AND_FEDERATION_H

#include <lasso/lasso.h>

xmlChar *lasso_build_url_encoded_message_authnRequest(LassoNode *);

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
									const char *consent);

#endif
