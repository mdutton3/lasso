#ifndef __NAME_IDENTIFIER_MAPPING_H__
#define __NAME_IDENTIFIER_MAPPING_H__

#include <lasso/lasso.h>

LassoNode *lasso_build_name_identifier_mappingRequest(const xmlChar *providerID,
						      LassoNode     *nameIdentifier,
						      const xmlChar *relayState);

LassoNode *lasso_build_name_identifier_mappingResponse(LassoNode     *request,
						       const xmlChar *providerID,
						       const xmlChar *codeValue,
						       const xmlChar *relayState);

#endif /* __NAME_IDENTIFIER_MAPPING_H__ */
