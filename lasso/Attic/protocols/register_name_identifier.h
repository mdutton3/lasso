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

#ifndef __LASSO_REGISTER_NAME_IDENTIFIER_H__
#define __LASSO_REGISTER_NAME_IDENTIFIER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/protocols/protocols.h>

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_REGISTER_NAME_IDENTIFIER_H__ */
