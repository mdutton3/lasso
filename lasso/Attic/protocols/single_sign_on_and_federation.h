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

#include <lasso/protocols/protocols.h>

typedef struct _lassoAuthnRequest lassoAuthnRequest;

struct _lassoAuthnRequest {
  LassoNode  *node;
};

typedef struct _lassoAuthnResponse lassoAuthnResponse;

struct _lassoAuthnResponse {
  LassoNode     *node;
  LassoNode     *request_node;
  xmlChar       *request_query;
  gboolean       isPassive;
  gboolean       mustAuthenticate;
  const xmlChar *public_key;
  const xmlChar *private_key;
  const xmlChar *certificate;
};

typedef struct _lassoRequest lassoRequest;

struct _lassoRequest {
  LassoNode  *node;
};

typedef struct _lassoResponse lassoResponse;

struct _lassoResponse {
  LassoNode     *node;
  xmlChar       *request_query;
  LassoNode     *request_node;
  gboolean       isPassive;
  gboolean       mustAuthenticate;
  const xmlChar *public_key;
  const xmlChar *private_key;
  const xmlChar *certificate;
};



lassoAuthnRequest *lasso_authn_request_create(const xmlChar *providerID,
					      const xmlChar *nameIDPolicy,
					      gint           forceAuthn,
					      gint           isPassive,
					      const xmlChar *protocolProfile,
					      const xmlChar *assertionConsumerServiceID,
					      GPtrArray     *authnContextClassRefs,
					      GPtrArray     *authnContextStatementRefs,
					      const xmlChar *authnContextComparison,
					      const xmlChar *relayState,
					      gint           proxyCount,
					      GPtrArray     *idpList,
					      const xmlChar *consent);

lassoAuthnResponse *lasso_authn_response_create(xmlChar       *query,
						gboolean       verifySignature,
						const xmlChar *public_key,
						const xmlChar *private_key,
						const xmlChar *certificate,
						gboolean       isAuthenticated);

gint lasso_authn_response_init(lassoAuthnResponse *lares,
			       const xmlChar      *providerID,
			       gboolean            authentication_result);

gint lasso_authn_response_add_assertion(lassoAuthnResponse *lares,
					LassoNode          *assertion);

LassoNode *lasso_assertion_build(gpointer       lares,
				 const xmlChar *issuer);

gint lasso_assertion_add_authenticationStatement(LassoNode *assertion,
						 LassoNode *statement);

LassoNode *lasso_authentication_statement_build(const xmlChar *authenticationMethod,
						const xmlChar *sessionIndex,
						const xmlChar *reauthenticateOnOrAfter,
						xmlChar       *nameIdentifier,
						const xmlChar *nameQualifier,
						const xmlChar *format,
						xmlChar       *idp_nameIdentifier,
						const xmlChar *idp_nameQualifier,
						const xmlChar *idp_format,
						const xmlChar *confirmationMethod);

lassoResponse *lasso_response_create(const xmlChar *serialized_request,
				     gboolean       verifySignature,
				     const xmlChar *public_key,
				     const xmlChar *private_key,
				     const xmlChar *certificate);

gint lasso_response_init(lassoResponse *lares,
			 gboolean       authentication_result);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SINGLE_SIGN_ON_AND_FEDERATION_H__ */
