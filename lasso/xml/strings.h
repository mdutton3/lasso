/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_STRINGS_H__
#define __LASSO_STRINGS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/export.h>
#include <libxml/xpath.h>

/*****************************************************************************/
/* Liberty Alliance                                                          */
/*****************************************************************************/

/* prefix & href */
LASSO_EXPORT_VAR const xmlChar lassoLibHRef[];
LASSO_EXPORT_VAR const xmlChar lassoLibPrefix[];

/* Versioning */
LASSO_EXPORT_VAR const xmlChar lassoLibMajorVersion[];
LASSO_EXPORT_VAR const xmlChar lassoLibMinorVersion[];

/* NameIDPolicyType */
LASSO_EXPORT_VAR const xmlChar lassoLibNameIDPolicyTypeNone[];
LASSO_EXPORT_VAR const xmlChar lassoLibNameIDPolicyTypeOneTime[];
LASSO_EXPORT_VAR const xmlChar lassoLibNameIDPolicyTypeFederated[];
LASSO_EXPORT_VAR const xmlChar lassoLibNameIDPolicyTypeAny[];

/* AuthnContextComparison */
LASSO_EXPORT_VAR const xmlChar lassoLibAuthnContextComparisonExact[];
LASSO_EXPORT_VAR const xmlChar lassoLibAuthnContextComparisonMinimum[];
LASSO_EXPORT_VAR const xmlChar lassoLibAuthnContextComparisonBetter[];

/* StatusCodes */
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeFederationDoesNotExist[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeInvalidAssertionConsumerServiceIndex[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeInvalidSignature[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeNoAuthnContext[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeNoAvailableIDP[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeNoPassive[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeNoSupportedIDP[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeProxyCountExceeded[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeUnknownPrincipal[];
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeUnsignedAuthnRequest[];

/* ProtocolProfile */
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileArtifact[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfilePost[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileFedTermIdpHttp[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileFedTermIdpSoap[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileFedTermSpHttp[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileFedTermSpSoap[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileRniIdpHttp[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileRniIdpSoap[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileRniSpHttp[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileRniSpSoap[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileSloSpHttp[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileSloSpSoap[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileSloIdpHttp[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileSloIdpSoap[];

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
LASSO_EXPORT_VAR const xmlChar lassoSamlAssertionHRef[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAssertionPrefix[];
LASSO_EXPORT_VAR const xmlChar lassoSamlProtocolHRef[];
LASSO_EXPORT_VAR const xmlChar lassoSamlProtocolPrefix[];

/* Versioning */
LASSO_EXPORT_VAR const xmlChar lassoSamlMajorVersion[];
LASSO_EXPORT_VAR const xmlChar lassoSamlMinorVersion[];

/* StatusCodes */
LASSO_EXPORT_VAR const xmlChar lassoSamlStatusCodeRequestDenied[];
LASSO_EXPORT_VAR const xmlChar lassoSamlStatusCodeSuccess[];

/* AuthenticationMethods */
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodPassword[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodKerberos[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodSecureRemotePassword[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodHardwareToken[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodSmartcardPki[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodSoftwarePki[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodPGP[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodSPki[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodXkms[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodXmlSign[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodUnspecified[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_STRINGS_H__ */
