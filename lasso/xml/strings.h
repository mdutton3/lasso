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

/*****************************************************************************/
/* Lasso                                                                     */
/*****************************************************************************/

/* prefix & href */
#define lassoLassoHRef	 "http://www.entrouvert.org/namespaces/lasso/0.0"
#define lassoLassoPrefix	 "lasso"

/*****************************************************************************/
/* Liberty Alliance                                                          */
/*****************************************************************************/

/* prefix & href */
#define lassoLibHRef	 "urn:liberty:iff:2003-08"
#define lassoLibPrefix	 "lib"

/* Versioning */
#define lassoLibMajorVersion	 "1"
#define lassoLibMinorVersion	 "2"

/* NameIDPolicyType */
#define lassoLibNameIDPolicyTypeNone	 "none"
#define lassoLibNameIDPolicyTypeOneTime	 "onetime"
#define lassoLibNameIDPolicyTypeFederated	 "federated"
#define lassoLibNameIDPolicyTypeAny	 "any"

/* AuthnContextComparison */
#define lassoLibAuthnContextComparisonExact	 "exact"
#define lassoLibAuthnContextComparisonMinimum	 "minimum"
#define lassoLibAuthnContextComparisonBetter	 "better"

/* StatusCodes */
#define lassoLibStatusCodeFederationDoesNotExist	       "lib:FederationDoesNotExist"
#define lassoLibStatusCodeInvalidAssertionConsumerServiceIndex "lib:InvalidAssertionConsumerServiceIndex"
#define lassoLibStatusCodeInvalidSignature	               "lib:InvalidSignature"
#define lassoLibStatusCodeNoAuthnContext	               "lib:NoAuthnContext"
#define lassoLibStatusCodeNoAvailableIDP	               "lib:NoAvailableIDP"
#define lassoLibStatusCodeNoPassive	                       "lib:NoPassive"
#define lassoLibStatusCodeNoSupportedIDP	               "lib:NoSupportedIDP"
#define lassoLibStatusCodeProxyCountExceeded	               "lib:ProxyCountExceeded"
#define lassoLibStatusCodeUnknownPrincipal	               "lib:UnknownPrincipal"
#define lassoLibStatusCodeUnsignedAuthnRequest	               "lib:UnsignedAuthnRequest"
#define lassoLibStatusCodeUnsupportedProfile	               "lib:UnsupportedProfile"

/* ProtocolProfile */
#define lassoLibProtocolProfileBrwsArt	         "http://projectliberty.org/profiles/brws-art"
#define lassoLibProtocolProfileBrwsPost	         "http://projectliberty.org/profiles/brws-post"
#define lassoLibProtocolProfileFedTermIdpHttp	 "http://projectliberty.org/profiles/fedterm-idp-http"
#define lassoLibProtocolProfileFedTermIdpSoap	 "http://projectliberty.org/profiles/fedterm-idp-soap"
#define lassoLibProtocolProfileFedTermSpHttp	 "http://projectliberty.org/profiles/fedterm-sp-http"
#define lassoLibProtocolProfileFedTermSpSoap	 "http://projectliberty.org/profiles/fedterm-sp-soap"
#define lassoLibProtocolProfileNimSpHttp         "http://projectliberty.org/profiles/nim-sp-http"
#define lassoLibProtocolProfileNimSpSoap         "http://projectliberty.org/profiles/nim-sp-soap"
#define lassoLibProtocolProfileRniIdpHttp	 "http://projectliberty.org/profiles/rni-idp-http"
#define lassoLibProtocolProfileRniIdpSoap	 "http://projectliberty.org/profiles/rni-idp-soap"
#define lassoLibProtocolProfileRniSpHttp	 "http://projectliberty.org/profiles/rni-sp-http"
#define lassoLibProtocolProfileRniSpSoap	 "http://projectliberty.org/profiles/rni-sp-soap"
#define lassoLibProtocolProfileSloSpHttp	 "http://projectliberty.org/profiles/slo-sp-http"
#define lassoLibProtocolProfileSloSpSoap	 "http://projectliberty.org/profiles/slo-sp-soap"
#define lassoLibProtocolProfileSloIdpHttp	 "http://projectliberty.org/profiles/slo-idp-http"
#define lassoLibProtocolProfileSloIdpSoap	 "http://projectliberty.org/profiles/slo-idp-soap"

/* NameIdentifier formats */
#define lassoLibNameIdentifierFormatFederated	 "urn:liberty:iff:nameid:federated"
#define lassoLibNameIdentifierFormatOneTime	 "urn:liberty:iff:nameid:one-time"
#define lassoLibNameIdentifierFormatEncrypted	 "urn:liberty:iff:nameid:encrypted"
#define lassoLibNameIdentifierFormatEntityID	 "urn:liberty:iff:nameid:entityID"

/* Consent */
#define lassoLibConsentObtained	 "urn:liberty:consent:obtained"
#define lassoLibConsentUnavailable	 "urn:liberty:consent:unavailable"
#define lassoLibConsentInapplicable	 "urn:liberty:consent:inapplicable"

/*****************************************************************************/
/* METADATA                                                                  */
/*****************************************************************************/

/* prefix & href */
#define lassoMetadataHRef	 "urn:liberty:metadata:2003-08"
#define lassoMetadataPrefix	 "md"

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
#define lassoSamlAssertionHRef	 "urn:oasis:names:tc:SAML:1.0:assertion"
#define lassoSamlAssertionPrefix	 "saml"
#define lassoSamlProtocolHRef	 "urn:oasis:names:tc:SAML:1.0:protocol"
#define lassoSamlProtocolPrefix	 "samlp"

/* Versioning */
#define lassoSamlMajorVersion	 "1"
#define lassoSamlMinorVersion	 "1"

/* StatusCodes */
#define lassoSamlStatusCodeSuccess	            "samlp:Success"
#define lassoSamlStatusCodeRequestDenied            "samlp:RequestDenied"
#define lassoSamlStatusCodeVersionMismatch          "samlp:VersionMismatch"
#define lassoSamlStatusCodeRequester                "samlp:Requester"
#define lassoSamlStatusCodeResponder                "samlp:Responder"
#define lassoSamlStatusCodeRequestVersionTooHigh    "samlp:RequestVersionTooHigh"
#define lassoSamlStatusCodeRequestVersionTooLow     "samlp:RequestVersionTooLow"
#define lassoSamlStatusCodeRequestVersionDeprecated "samlp:RequestVersionDeprecated"
#define lassoSamlStatusCodeTooManyResponses         "samlp:TooManyResponses"
#define lassoSamlStatusCodeResourceNotRecognized    "samlp:ResourceNotRecognized"

/* AuthenticationMethods */
#define lassoSamlAuthenticationMethodPassword	 "urn:oasis:names:tc:SAML:1.0:am:password"
#define lassoSamlAuthenticationMethodKerberos	 "urn:ietf:rfc:1510"
#define lassoSamlAuthenticationMethodSecureRemotePassword	 "urn:ietf:rfc:2945"
#define lassoSamlAuthenticationMethodHardwareToken	 "urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define lassoSamlAuthenticationMethodSmartcardPki	 "urn:ietf:rfc:2246"
#define lassoSamlAuthenticationMethodSoftwarePki	 "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define lassoSamlAuthenticationMethodPgp	 "urn:oasis:names:tc:SAML:1.0:am:PGP"
#define lassoSamlAuthenticationMethodSPki	 "urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define lassoSamlAuthenticationMethodXkms	 "urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define lassoSamlAuthenticationMethodXmlDSig	 "urn:ietf:rfc:3075"
#define lassoSamlAuthenticationMethodUnspecified	 "urn:oasis:names:tc:SAML:1.0:am:unspecified"

/* ConfirmationMethods */
#define lassoSamlConfirmationMethodArtifact01	 "urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
#define lassoSamlConfirmationMethodBearer	 "urn:oasis:names:tc:SAML:1.0:cm:bearer"
#define lassoSamlConfirmationMethodHolderOfKey	 "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
#define lassoSamlConfirmationMethodSenderVouches	 "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"

/*****************************************************************************/
/* SOAP                                                                      */
/*****************************************************************************/

/* prefix & href */
#define lassoSoapEnvHRef	 "http://schemas.xmlsoap.org/soap/envelope/"
#define lassoSoapEnvPrefix	 "soap-env"

/*****************************************************************************/
/* Others                                                                    */
/*****************************************************************************/

/* xsi prefix & href */
#define lassoXsiHRef "http://www.w3.org/2001/XMLSchema-instance"
#define lassoXsiPrefix "xsi"

#endif /* __LASSO_STRINGS_H__ */
