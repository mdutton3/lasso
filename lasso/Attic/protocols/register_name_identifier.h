#ifndef __REGISTER_NAME_IDENTIFIER_H__
#define __REGISTER_NAME_IDENTIFIER_H__

#include <lasso/lasso.h>

LassoNode *lasso_build_full_registerNameIdentifierRequest(const xmlChar *requestID,
							  const xmlChar *majorVersion,
							  const xmlChar *minorVersion,
							  const xmlChar *issueInstant,
							  const xmlChar *providerID,
							  LassoNode     *idpProvidedNameIdentifer,
							  LassoNode     *spProvidedNameIdentifier,
							  LassoNode     *oldProvidedNameIdentifier,
							  const xmlChar *relayState);

LassoNode *lasso_build_registerNameIdentifierRequest(const xmlChar *providerID,
						     LassoNode     *idpProvidedNameIdentifer,
						     LassoNode     *spProvidedNameIdentifier,
						     LassoNode     *oldProvidedNameIdentifier,
						     const xmlChar *relayState);

LassoNode *lasso_build_full_registerNameIdentifierResponse(const xmlChar *responseID,
							   const xmlChar *majorVersion,
							   const xmlChar *minorVersion,
							   const xmlChar *issueInstant,
							   const xmlChar *inResponseTo,
							   const xmlChar *recipient,
							   const xmlChar *providerID,
							   const xmlChar *statusCodeValue,
							   const xmlChar *relayState);

LassoNode *lasso_build_registerNameIdentifierResponse(LassoNode     *request,
						      const xmlChar *providerID,
						      const xmlChar *statusCodeValue,
						      const xmlChar *relayState);

#endif /* __REGISTER_NAME_IDENTIFIER_H__ */
