#ifndef __REGISTER_NAME_IDENTIFIER_H__
#define __REGISTER_NAME_IDENTIFIER_H__

#include <lasso/lasso.h>

xmlChar *lasso_build_url_encoded_message_registerNameIdentifierRequest(LassoNode *);

LassoNode *lasso_build_registerNameIdentifierRequest(const char *metadata,
													 LassoNode  *idpProvidedNameIdentifer,
													 LassoNode  *spProvidedNameIdentifier,
													 LassoNode  *oldProvidedNameIdentifier,
													 const char *relayState);

xmlChar *lasso_build_url_encoded_message_registerNameIdentifierResponse(LassoNode *);

LassoNode *lasso_build_registerNameIdentifierResponse(LassoNode  *request,
													  const char*codeValue,
													  const char*relayState);


#endif /* __REGISTER_NAME_IDENTIFIER_H__ */
