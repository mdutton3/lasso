#ifndef SINGLE_SIGN_ON_AND_FEDERATION_H
#define SINGLE_SIGN_ON_AND_FEDERATION_H

#include <lasso/lasso.h>
#include <glib.h>

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

LassoNode *lasso_build_authnResponse(LassoNode *request,
				     const xmlChar *providerID);

LassoNode *lasso_build_response(LassoNode *request,
				const xmlChar *providerID);
#endif
