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
const xmlChar lassoLibHRef[]   = "urn:liberty:iff:2003-08";
const xmlChar lassoLibPrefix[] = "lib";

/* Versioning */
const xmlChar lassoLibMajorVersion[] = "1";
const xmlChar lassoLibMinorVersion[] = "2";

/* NameIDPolicyType */
const xmlChar lassoLibNameIDPolicyTypeNone[]      = "none";
const xmlChar lassoLibNameIDPolicyTypeOneTime[]   = "onetime";
const xmlChar lassoLibNameIDPolicyTypeFederated[] = "federated";
const xmlChar lassoLibNameIDPolicyTypeAny[]       = "any";

/* AuthnContextComparison */
const xmlChar lassoLibAuthnContextComparisonExact[]   = "exact";
const xmlChar lassoLibAuthnContextComparisonMinimum[] = "minimum";
const xmlChar lassoLibAuthnContextComparisonBetter[]  = "better";

/* StatusCodes */
const xmlChar lassoLibStatusCodeFederationDoesNotExist[]               = "lib:FederationDoesNotExist";
const xmlChar lassoLibStatusCodeInvalidAssertionConsumerServiceIndex[] = "lib:InvalidAssertionConsumerServiceIndex";
const xmlChar lassoLibStatusCodeInvalidSignature[]                     = "lib:InvalidSignature";
const xmlChar lassoLibStatusCodeNoAuthnContext[]                       = "lib:NoAuthnContext";
const xmlChar lassoLibStatusCodeNoAvailableIDP[]                       = "lib:NoAvailableIDP";
const xmlChar lassoLibStatusCodeNoPassive[]                            = "lib:NoPassive";
const xmlChar lassoLibStatusCodeNoSupportedIDP[]                       = "lib:NoSupportedIDP";
const xmlChar lassoLibStatusCodeProxyCountExceeded[]                   = "lib:ProxyCountExceeded";
const xmlChar lassoLibStatusCodeUnknownPrincipal[]                     = "lib:UnknownPrincipal";
const xmlChar lassoLibStatusCodeUnsignedAuthnRequest[]                 = "lib:UnsignedAuthnRequest";

/* ProtocolProfile */
const xmlChar lassoLibProtocolProfileArtifact[]       = "http://projectliberty.org/profiles/brws-art";
const xmlChar lassoLibProtocolProfilePost[]           = "http://projectliberty.org/profiles/brws-post";
const xmlChar lassoLibProtocolProfileFedTermIdpHttp[] = "http://projectliberty.org/profiles/fedterm-idp-http";
const xmlChar lassoLibProtocolProfileFedTermIdpSoap[] = "http://projectliberty.org/profiles/fedterm-idp-soap";
const xmlChar lassoLibProtocolProfileFedTermSpHttp[]  = "http://projectliberty.org/profiles/fedterm-sp-http";
const xmlChar lassoLibProtocolProfileFedTermSpSoap[]  = "http://projectliberty.org/profiles/fedterm-sp-soap";
const xmlChar lassoLibProtocolProfileRniIdpHttp[]     = "http://projectliberty.org/profiles/rni-idp-http";
const xmlChar lassoLibProtocolProfileRniIdpSoap[]     = "http://projectliberty.org/profiles/rni-idp-soap";
const xmlChar lassoLibProtocolProfileRniSpHttp[]      = "http://projectliberty.org/profiles/rni-sp-http";
const xmlChar lassoLibProtocolProfileRniSpSoap[]      = "http://projectliberty.org/profiles/rni-sp-soap";
const xmlChar lassoLibProtocolProfileSloSpHttp[]      = "http://projectliberty.org/profiles/slo-sp-http";
const xmlChar lassoLibProtocolProfileSloSpSoap[]      = "http://projectliberty.org/profiles/slo-sp-soap";
const xmlChar lassoLibProtocolProfileSloIdpHttp[]     = "http://projectliberty.org/profiles/slo-idp-http";
const xmlChar lassoLibProtocolProfileSloIdpSoap[]     = "http://projectliberty.org/profiles/slo-idp-soap";

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
const xmlChar lassoSamlAssertionHRef[]   = "urn:oasis:names:tc:SAML:1.0:assertion";
const xmlChar lassoSamlAssertionPrefix[] = "saml";
const xmlChar lassoSamlProtocolHRef[]    = "urn:oasis:names:tc:SAML:1.0:protocol";
const xmlChar lassoSamlProtocolPrefix[]  = "samlp";

/* Versioning */
const xmlChar lassoSamlMajorVersion[] = "1";
const xmlChar lassoSamlMinorVersion[] = "0";

/* StatusCodes */
const xmlChar lassoSamlStatusCodeRequestDenied[] = "Samlp:RequestDenied";
const xmlChar lassoSamlStatusCodeSuccess[]       = "Samlp:Success";

/* AuthenticationMethods */
const xmlChar lassoSamlAuthenticationMethodPassword[]             = "urn:oasis:names:tc:SAML:1.0:am:password";
const xmlChar lassoSamlAuthenticationMethodKerberos[]             = "urn:ietf:rfc:1510";
const xmlChar lassoSamlAuthenticationMethodSecureRemotePassword[] = "urn:ietf:rfc:2945";
const xmlChar lassoSamlAuthenticationMethodHardwareToken[]        = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";
const xmlChar lassoSamlAuthenticationMethodSmartcardPki[]         = "urn:ietf:rfc:2246";
const xmlChar lassoSamlAuthenticationMethodSoftwarePki[]          = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";
const xmlChar lassoSamlAuthenticationMethodPGP[]                  = "urn:oasis:names:tc:SAML:1.0:am:PGP";
const xmlChar lassoSamlAuthenticationMethodSPki[]                 = "urn:oasis:names:tc:SAML:1.0:am:SPKI";
const xmlChar lassoSamlAuthenticationMethodXkms[]                 = "urn:oasis:names:tc:SAML:1.0:am:XKMS";
const xmlChar lassoSamlAuthenticationMethodXmlSign[]              = "urn:ietf:rfc:3075";
const xmlChar lassoSamlAuthenticationMethodUnspecified[]          = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

/* ConfirmationMethods */
const xmlChar lassoSamlConfirmationMethodArtifact01[]    = "urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
const xmlChar lassoSamlConfirmationMethodBearer[]        = "urn:oasis:names:tc:SAML:1.1:cm:bearer"
const xmlChar lassoSamlConfirmationMethodHolderOfKey[]   = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
const xmlChar lassoSamlConfirmationMethodSenderVouches[] = "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"
