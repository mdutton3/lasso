/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_SINGLE_SIGN_ON_AND_FEDERATION_H__
#define __LASSO_SINGLE_SIGN_ON_AND_FEDERATION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/lasso.h>

LassoNode *lasso_build_authnRequest_must_autenthicate(gboolean       verifySignature,
						      xmlChar       *query,
						      const xmlChar *rsapub,
						      const xmlChar *rsakey,
						      gboolean       isAuthenticated,
						      gboolean      *isPassive,
						      gboolean      *mustAuthenticate,
						      GPtrArray     *authenticationMethods,
						      xmlChar       *authnContextComparison);

LassoNode *lasso_build_authnRequest(const xmlChar *providerID,
				    const xmlChar *nameIDPolicy,
				    const xmlChar *forceAuthn,
				    const xmlChar *isPassive,
				    const xmlChar *protocolProfile,
				    const xmlChar *assertionConsumerServiceID,
				    GPtrArray     *authnContextClassRefs,
				    GPtrArray     *authnContextStatementRefs,
				    const xmlChar *authnContextComparison,
				    const xmlChar *relayState,
				    gint           proxyCount,
				    GPtrArray     *idpList,
				    const xmlChar *consent);

LassoNode *lasso_build_full_authnResponse(LassoNode     *request,
					  const xmlChar *providerID);

LassoNode *lasso_build_full_response(LassoNode     *request,
				     const xmlChar *providerID);

LassoNode *lasso_build_assertion(const xmlChar *inResponseTo,
				 const xmlChar *issuer);

LassoNode *lasso_build_authenticationStatement(const xmlChar *authenticationMethod,
					       LassoNode     *nameIdentifier,
					       LassoNode     *idpProvidedNameIdentifier);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SINGLE_SIGN_ON_AND_FEDERATION_H__ */
