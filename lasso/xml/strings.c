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

#include <lasso/lasso.h>

/*****************************************************************************/
/* Liberty Alliance                                                          */
/*****************************************************************************/

/* prefix & href */
const gchar lassoLibHRef[]   = "urn:liberty:iff:2003-08";
const gchar lassoLibPrefix[] = "lib";

/* Versioning */
const gchar lassoLibMajorVersion[] = "1";
const gchar lassoLibMinorVersion[] = "2";

/* NameIDPolicyType */
const gchar lassoLibNameIDPolicyTypeNone[]      = "none";
const gchar lassoLibNameIDPolicyTypeOneTime[]   = "onetime";
const gchar lassoLibNameIDPolicyTypeFederated[] = "federated";
const gchar lassoLibNameIDPolicyTypeAny[]       = "any";

/* AuthnContextComparison */
const gchar lassoLibAuthnContextComparisonExact[]   = "exact";
const gchar lassoLibAuthnContextComparisonMinimum[] = "minimum";
const gchar lassoLibAuthnContextComparisonBetter[]  = "better";

/* StatusCodes */
const gchar lassoLibStatusCodeFederationDoesNotExist[] = "lib:FederationDoesNotExist";
const gchar lassoLibStatusCodeNoPassive[]              = "lib:NoPassive";

/* ProtocolProfile */
const gchar lassoLibProtocolProfileArtifact[]       = "http://projectliberty.org/profiles/brws-art";
const gchar lassoLibProtocolProfilePost[]           = "http://projectliberty.org/profiles/brws-post";
const gchar lassoLibProtocolProfileFedTermIdpHttp[] = "http://projectliberty.org/profiles/fedterm-idp-http";
const gchar lassoLibProtocolProfileFedTermIdpSoap[] = "http://projectliberty.org/profiles/fedterm-idp-soap";
const gchar lassoLibProtocolProfileFedTermSpHttp[]  = "http://projectliberty.org/profiles/fedterm-sp-http";
const gchar lassoLibProtocolProfileFedTermSpSoap[]  = "http://projectliberty.org/profiles/fedterm-sp-soap";
const gchar lassoLibProtocolProfileRniIdpHttp[]     = "http://projectliberty.org/profiles/rni-idp-http";
const gchar lassoLibProtocolProfileRniIdpSoap[]     = "http://projectliberty.org/profiles/rni-idp-soap";
const gchar lassoLibProtocolProfileRniSpHttp[]      = "http://projectliberty.org/profiles/rni-sp-http";
const gchar lassoLibProtocolProfileRniSpSoap[]      = "http://projectliberty.org/profiles/rni-sp-soap";
const gchar lassoLibProtocolProfileSloSpHttp[]      = "http://projectliberty.org/profiles/slo-sp-http";
const gchar lassoLibProtocolProfileSloSpSoap[]      = "http://projectliberty.org/profiles/slo-sp-soap";
const gchar lassoLibProtocolProfileSloIdpHttp[]     = "http://projectliberty.org/profiles/slo-idp-http";
const gchar lassoLibProtocolProfileSloIdpSoap[]     = "http://projectliberty.org/profiles/slo-idp-soap";

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
const gchar lassoSamlAssertionHRef[]   = "urn:oasis:names:tc:SAML:1.0:assertion";
const gchar lassoSamlAssertionPrefix[] = "saml";
const gchar lassoSamlProtocolHRef[]    = "urn:oasis:names:tc:SAML:1.0:protocol";
const gchar lassoSamlProtocolPrefix[]  = "samlp";

/* Versioning */
const gchar lassoSamlMajorVersion[] = "1";
const gchar lassoSamlMinorVersion[] = "0";

/* StatusCodes */
const gchar lassoSamlStatusCodeRequestDenied[] = "Samlp:RequestDenied";
const gchar lassoSamlStatusCodeSuccess[]       = "Samlp:Success";

/* AuthenticationMethods */
const gchar lassoSamlAuthenticationMethodPassword[]             = "urn:oasis:names:tc:SAML:1.0:am:password";
const gchar lassoSamlAuthenticationMethodKerberos[]             = "urn:ietf:rfc:1510";
const gchar lassoSamlAuthenticationMethodSecureRemotePassword[] = "urn:ietf:rfc:2945";
const gchar lassoSamlAuthenticationMethodHardwareToken[]        = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";
const gchar lassoSamlAuthenticationMethodSmartcardPki[]         = "urn:ietf:rfc:2246";
const gchar lassoSamlAuthenticationMethodSoftwarePki[]          = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";
const gchar lassoSamlAuthenticationMethodPGP[]                  = "urn:oasis:names:tc:SAML:1.0:am:PGP";
const gchar lassoSamlAuthenticationMethodSPki[]                 = "urn:oasis:names:tc:SAML:1.0:am:SPKI";
const gchar lassoSamlAuthenticationMethodXkms[]                 = "urn:oasis:names:tc:SAML:1.0:am:XKMS";
const gchar lassoSamlAuthenticationMethodXmlSign[]              = "urn:ietf:rfc:3075";
const gchar lassoSamlAuthenticationMethodUnspecified[]          = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

