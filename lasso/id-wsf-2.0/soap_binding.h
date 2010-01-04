/* $Id: wsf_profile.h,v 1.13 2006/11/14 17:07:30 Exp $
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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

#ifndef __LASSO_IDWSF2_SOAP_BINDING_H__
#define __LASSO_IDWSF2_SOAP_BINDING_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../export.h"
#include "../xml/soap_envelope.h"
#include "../xml/id-wsf-2.0/sb2_target_identity.h"
#include "../xml/ws/wsse_security_header.h"
#include "../xml/saml-2.0/saml2_assertion.h"

LASSO_EXPORT char* lasso_soap_envelope_sb2_get_provider_id(LassoSoapEnvelope *soap_envelope);

LASSO_EXPORT char* lasso_soap_envelope_sb2_get_redirect_request_url(
		LassoSoapEnvelope *soap_envelope);

LASSO_EXPORT LassoIdWsf2Sb2TargetIdentity* lasso_soap_envelope_sb2_get_target_identity_header(
		LassoSoapEnvelope *soap_envelope);

LASSO_EXPORT LassoWsSec1SecurityHeader* lasso_soap_envelope_wssec_get_security_header(
		LassoSoapEnvelope *soap_envelope);

LASSO_EXPORT void lasso_soap_envelope_add_security_token(LassoSoapEnvelope *soap_envelope,
		LassoNode *token);

LASSO_EXPORT LassoSaml2Assertion *lasso_soap_envelope_get_saml2_security_token(
		LassoSoapEnvelope *soap_envelope);

LASSO_EXPORT const char* lasso_soap_envelope_get_action(LassoSoapEnvelope *soap_envelope);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SOAP_BINDING_H__ */

