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
#include <glib-object.h>

/*****************************************************************************/
/* Liberty Alliance                                                          */
/*****************************************************************************/

/* Versioning */
LASSO_EXPORT_VAR const gchar lassoLibMajorVersion[];
LASSO_EXPORT_VAR const gchar lassoLibMinorVersion[];

/* NameIDPolicyType */
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeNone[];
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeOneTime[];
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeFederated[];
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeAny[];

/* AuthnContextComparison */
LASSO_EXPORT_VAR const gchar lassoLibAuthnContextComparisonExact[];
LASSO_EXPORT_VAR const gchar lassoLibAuthnContextComparisonMinimum[];
LASSO_EXPORT_VAR const gchar lassoLibAuthnContextComparisonBetter[];

/* StatusCodes */
LASSO_EXPORT_VAR const gchar lassoLibStatusCodeFederationDoesNotExist[];
LASSO_EXPORT_VAR const gchar lassoLibStatusCodeNoPassive[];

/* ProtocolProfile */
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileArtifact[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfilePost[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileFedTermIdpHttp[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileFedTermIdpSoap[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileFedTermSpHttp[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileFedTermSpSoap[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileRniIdpHttp[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileRniIdpSoap[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileRniSpHttp[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileRniSpSoap[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileSloSpHttp[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileSloSpSoap[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileSloIdpHttp[];
LASSO_EXPORT_VAR const gchar lassoLibProtocolProfileSloIdpSoap[];

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* Versioning */
LASSO_EXPORT_VAR const gchar lassoSamlMajorVersion[];
LASSO_EXPORT_VAR const gchar lassoSamlMinorVersion[];

/* StatusCodes */
LASSO_EXPORT_VAR const gchar lassoSamlStatusCodeRequestDenied[];
LASSO_EXPORT_VAR const gchar lassoSamlStatusCodeSuccess[];

/* AuthenticationMethods */
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodPassword[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodKerberos[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodSecureRemotePassword[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodHardwareToken[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodSmartcardPki[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodSoftwarePki[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodPGP[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodSPki[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodXkms[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodXmlSign[];
LASSO_EXPORT_VAR const gchar lassoSamlAuthenticationMethodUnspecified[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_STRINGS_H__ */
