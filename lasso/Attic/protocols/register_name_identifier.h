#ifndef __REGISTER_NAME_IDENTIFIER_H__
#define __REGISTER_NAME_IDENTIFIER_H__

#include <lasso/lasso.h>

LassoNode *lasso_build_registerNameIdentifierRequest(const xmlChar *providerID,
						     LassoNode     *idpProvidedNameIdentifer,
						     LassoNode     *spProvidedNameIdentifier,
						     LassoNode     *oldProvidedNameIdentifier,
						     const xmlChar *relayState);

LassoNode *lasso_build_registerNameIdentifierResponse(LassoNode     *request,
						      const xmlChar *providerID,
						      const xmlChar *codeValue,
						      const xmlChar *relayState);

#endif /* __REGISTER_NAME_IDENTIFIER_H__ */
