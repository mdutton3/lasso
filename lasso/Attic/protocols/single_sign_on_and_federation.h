#ifndef SINGLE_SIGN_ON_AND_FEDERATION_H
#define SINGLE_SIGN_ON_AND_FEDERATION_H

#include <lasso/lasso.h>

xmlChar *lasso_build_url_encoded_message_authnRequest(LassoNode *);

LassoNode *lasso_build_authnRequest(const xmlChar *providerID,
				    const xmlChar *nameIDPolicy,
				    const xmlChar *isPassive,
				    const xmlChar *forceAuthn,
				    const xmlChar *assertionConsumerServiceID,
				    const xmlChar **authnContextClassRefs,
				    const xmlChar **authnContextStatementRefs,
				    const xmlChar *authnContextComparison,
				    const xmlChar *relayState,
				    const xmlChar *proxyCount,
				    const xmlChar **idpList,
				    const xmlChar *consent);

#endif
