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
#define LASSO_LASSO_HREF	 "http://www.entrouvert.org/namespaces/lasso/0.0"
#define LASSO_LASSO_PREFIX "lasso"

/*****************************************************************************/
/* Liberty Alliance                                                          */
/*****************************************************************************/

/* prefix & href */
#define LASSO_LIB_HREF	 "urn:liberty:iff:2003-08"
#define LASSO_LIB_PREFIX	 "lib"

/* Versioning */
#define LASSO_LIB_MAJOR_VERSION_N	 1
#define LASSO_LIB_MINOR_VERSION_N	 2

/* NameIDPolicyType */
#define LASSO_LIB_NAMEID_POLICY_TYPE_NONE	 "none"
#define LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME	 "onetime"
#define LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED	 "federated"
#define LASSO_LIB_NAMEID_POLICY_TYPE_ANY	 "any"

/* AuthnContextComparison */
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_EXACT	 "exact"
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MINIMUM	 "minimum"
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_BETTER	 "better"

/* StatusCodes */
#define LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST	       "lib:FederationDoesNotExist"
#define LASSO_LIB_STATUS_CODE_INVALID_ASSERTION_CONSUMER_SERVICE_INDEX "lib:InvalidAssertionConsumerServiceIndex"
#define LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE	               "lib:InvalidSignature"
#define LASSO_LIB_STATUS_CODE_NO_AUTHN_CONTEXT	               "lib:NoAuthnContext"
#define LASSO_LIB_STATUS_CODE_NO_AVAILABLEIDP	               "lib:NoAvailableIDP"
#define LASSO_LIB_STATUS_CODE_NO_PASSIVE	                       "lib:NoPassive"
#define LASSO_LIB_STATUS_CODE_NO_SUPPORTEDIDP	               "lib:NoSupportedIDP"
#define LASSO_LIB_STATUS_CODE_PROXY_COUNT_EXCEEDED	               "lib:ProxyCountExceeded"
#define LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL	               "lib:UnknownPrincipal"
#define LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST	               "lib:UnsignedAuthnRequest"
#define LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE	               "lib:UnsupportedProfile"

/* ProtocolProfile */
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART	         "http://projectliberty.org/profiles/brws-art"
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST	         "http://projectliberty.org/profiles/brws-post"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_HTTP	 "http://projectliberty.org/profiles/fedterm-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_SOAP	 "http://projectliberty.org/profiles/fedterm-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_HTTP	 "http://projectliberty.org/profiles/fedterm-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_SOAP	 "http://projectliberty.org/profiles/fedterm-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_NIM_SP_HTTP         "http://projectliberty.org/profiles/nim-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_HTTP	 "http://projectliberty.org/profiles/rni-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_SOAP	 "http://projectliberty.org/profiles/rni-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_HTTP	 "http://projectliberty.org/profiles/rni-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_SOAP	 "http://projectliberty.org/profiles/rni-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_HTTP	 "http://projectliberty.org/profiles/slo-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP	 "http://projectliberty.org/profiles/slo-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_HTTP	 "http://projectliberty.org/profiles/slo-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_SOAP	 "http://projectliberty.org/profiles/slo-idp-soap"

/* NameIdentifier formats */
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED	 "urn:liberty:iff:nameid:federated"
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME	 "urn:liberty:iff:nameid:one-time"
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENCRYPTED	 "urn:liberty:iff:nameid:encrypted"
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENTITYID	 "urn:liberty:iff:nameid:entityID"

/* Consent */
#define LASSO_LIB_CONSENT_OBTAINED	               "urn:liberty:consent:obtained"
#define LASSO_LIB_CONSENT_OBTAINED_PRIOR           "urn:liberty:consent:obtained:prior"
#define LASSO_LIB_CONSENT_OBTAINED_CURRENT_IMPLICIT "urn:liberty:consent:obtained:current:implicit"
#define LASSO_LIB_CONSENT_OBTAINED_CURRENT_EXPLICIT "urn:liberty:consent:obtained:current:explicit"
#define LASSO_LIB_CONSENT_UNAVAILABLE	       "urn:liberty:consent:unavailable"
#define LASSO_LIB_CONSENT_INAPPLICABLE	       "urn:liberty:consent:inapplicable"

/*****************************************************************************/
/* METADATA                                                                  */
/*****************************************************************************/

/* prefix & href */
#define LASSO_METADATA_HREF	 "urn:liberty:metadata:2003-08"
#define LASSO_METADATA_PREFIX	 "md"

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
#define LASSO_SAML_ASSERTION_HREF	 "urn:oasis:names:tc:SAML:1.0:assertion"
#define LASSO_SAML_ASSERTION_PREFIX "saml"
#define LASSO_SAML_PROTOCOL_HREF	 "urn:oasis:names:tc:SAML:1.0:protocol"
#define LASSO_SAML_PROTOCOL_PREFIX	 "samlp"

/* Versioning */
#define LASSO_SAML_MAJOR_VERSION_N	 1
#define LASSO_SAML_MINOR_VERSION_N	 1

/* StatusCodes */
#define LASSO_SAML_STATUS_CODE_SUCCESS	            "samlp:Success"
#define LASSO_SAML_STATUS_CODE_REQUEST_DENIED            "samlp:RequestDenied"
#define LASSO_SAML_STATUS_CODE_VERSION_MISMATCH          "samlp:VersionMismatch"
#define LASSO_SAML_STATUS_CODE_REQUESTER                "samlp:Requester"
#define LASSO_SAML_STATUS_CODE_RESPONDER                "samlp:Responder"
#define LASSO_SAML_STATUS_CODE_REQUEST_VERSION_TOO_HIGH    "samlp:RequestVersionTooHigh"
#define LASSO_SAML_STATUS_CODE_REQUEST_VERSION_TOO_LOW     "samlp:RequestVersionTooLow"
#define LASSO_SAML_STATUS_CODE_REQUEST_VERSION_DEPRECATED "samlp:RequestVersionDeprecated"
#define LASSO_SAML_STATUS_CODE_TOO_MANY_RESPONSES         "samlp:TooManyResponses"
#define LASSO_SAML_STATUS_CODE_RESOURCE_NOT_RECOGNIZED    "samlp:ResourceNotRecognized"

/* AuthenticationMethods */
#define LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD	 "urn:oasis:names:tc:SAML:1.0:am:password"
#define LASSO_SAML_AUTHENTICATION_METHOD_KERBEROS	 "urn:ietf:rfc:1510"
#define LASSO_SAML_AUTHENTICATION_METHOD_SECURE_REMOTE_PASSWORD	 "urn:ietf:rfc:2945"
#define LASSO_SAML_AUTHENTICATION_METHOD_HARDWARE_TOKEN	 "urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define LASSO_SAML_AUTHENTICATION_METHOD_SMARTCARD_PKI	 "urn:ietf:rfc:2246"
#define LASSO_SAML_AUTHENTICATION_METHOD_SOFTWARE_PKI	 "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define LASSO_SAML_AUTHENTICATION_METHOD_PGP	 "urn:oasis:names:tc:SAML:1.0:am:PGP"
#define LASSO_SAML_AUTHENTICATION_METHODS_PKI	 "urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define LASSO_SAML_AUTHENTICATION_METHOD_XKMS	 "urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define LASSO_SAML_AUTHENTICATION_METHOD_XMLD_SIG	 "urn:ietf:rfc:3075"
#define LASSO_SAML_AUTHENTICATION_METHOD_UNSPECIFIED	 "urn:oasis:names:tc:SAML:1.0:am:unspecified"

/* ConfirmationMethods */
#define LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01	 "urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
#define LASSO_SAML_CONFIRMATION_METHOD_BEARER	 "urn:oasis:names:tc:SAML:1.0:cm:bearer"
#define LASSO_SAML_CONFIRMATION_METHOD_HOLDER_OF_KEY	 "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
#define LASSO_SAML_CONFIRMATION_METHOD_SENDER_VOUCHES	 "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"

/*****************************************************************************/
/* SOAP                                                                      */
/*****************************************************************************/

/* prefix & href */
#define LASSO_SOAP_ENV_HREF	 "http://schemas.xmlsoap.org/soap/envelope/"
#define LASSO_SOAP_ENV_PREFIX	 "soap-env"

/*****************************************************************************/
/* Others                                                                    */
/*****************************************************************************/

/* xsi prefix & href */
#define LASSO_XSI_HREF "http://www.w3.org/2001/XMLSchema-instance"
#define LASSO_XSI_PREFIX "xsi"

#endif /* __LASSO_STRINGS_H__ */
