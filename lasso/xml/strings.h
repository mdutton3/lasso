/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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
#include <libxml/tree.h>

/*****************************************************************************/
/* Lasso                                                                     */
/*****************************************************************************/

/* prefix & href */
LASSO_EXPORT_VAR const xmlChar lassoLassoHRef[];
LASSO_EXPORT_VAR const xmlChar lassoLassoPrefix[];

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
LASSO_EXPORT_VAR const xmlChar lassoLibStatusCodeUnsupportedProfile[];

/* ProtocolProfile */
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileSSOGet[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileSSOPost[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileBrwsArt[];
LASSO_EXPORT_VAR const xmlChar lassoLibProtocolProfileBrwsPost[];
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

/* NameIdentifier formats */
LASSO_EXPORT_VAR const xmlChar lassoLibNameIdentifierFormatFederated[];
LASSO_EXPORT_VAR const xmlChar lassoLibNameIdentifierFormatOneTime[];
LASSO_EXPORT_VAR const xmlChar lassoLibNameIdentifierFormatEncrypted[];
LASSO_EXPORT_VAR const xmlChar lassoLibNameIdentifierFormatEntityID[];

/* Consent */
LASSO_EXPORT_VAR const xmlChar lassoLibConsentObtained[];
LASSO_EXPORT_VAR const xmlChar lassoLibConsentUnavailable[];
LASSO_EXPORT_VAR const xmlChar lassoLibConsentInapplicable[];

/*****************************************************************************/
/* METADATA                                                                  */
/*****************************************************************************/

/* prefix & href */
LASSO_EXPORT_VAR const xmlChar lassoMetadataHRef[];
LASSO_EXPORT_VAR const xmlChar lassoMetadataPrefix[];

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
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodPgp[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodSPki[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodXkms[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodXmlDSig[];
LASSO_EXPORT_VAR const xmlChar lassoSamlAuthenticationMethodUnspecified[];

/* ConfirmationMethods */
LASSO_EXPORT_VAR const xmlChar lassoSamlConfirmationMethodArtifact01[];
LASSO_EXPORT_VAR const xmlChar lassoSamlConfirmationMethodBearer[];
LASSO_EXPORT_VAR const xmlChar lassoSamlConfirmationMethodHolderOfKey[];
LASSO_EXPORT_VAR const xmlChar lassoSamlConfirmationMethodSenderVouches[];

/*****************************************************************************/
/* SOAP                                                                      */
/*****************************************************************************/

/* prefix & href */
LASSO_EXPORT_VAR const xmlChar lassoSoapEnvHRef[];
LASSO_EXPORT_VAR const xmlChar lassoSoapEnvPrefix[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_STRINGS_H__ */
