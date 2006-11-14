/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#ifndef __LASSO_STRINGS_H__
#define __LASSO_STRINGS_H__

/* prefix & href */
#define LASSO_DS_HREF   "http://www.w3.org/2000/09/xmldsig#"
#define LASSO_DS_PREFIX "ds"

/*****************************************************************************/
/* Lasso                                                                     */
/*****************************************************************************/

/* prefix & href */
#define LASSO_LASSO_HREF   "http://www.entrouvert.org/namespaces/lasso/0.0"
#define LASSO_LASSO_PREFIX "lasso"

/*****************************************************************************/
/* Liberty Alliance ID-FF                                                    */
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

/* AuthenticationClassRef */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_INTERNET_PROTOCOL \
	"http://www.projectliberty.org/schemas/authctx/classes/InternetProtocol"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_INTERNET_PROTOCOL_PASSWORD \
	"http://www.projectliberty.org/schemas/authctx/classes/InternetProtocolPassword"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_UNREGISTERED \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileOneFactorUnregistered"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_UNREGISTERED \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileTwoFactorUnregistered"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_CONTRACT \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileOneFactorContract"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_CONTRACT \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileTwoFactorContract"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD \
	"http://www.projectliberty.org/schemas/authctx/classes/Password"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD_PROTECTED_TRANSPORT \
	"http://www.projectliberty.org/schemas/authctx/classes/PasswordProtectedTransport"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PREVIOUS_SESSION \
	"http://www.projectliberty.org/schemas/authctx/classes/PreviousSession"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SMARTCARD \
	"http://www.projectliberty.org/schemas/authctx/classes/Smartcard"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SMARTCARD_PKI \
	"http://www.projectliberty.org/schemas/authctx/classes/SmartcardPKI"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SOFTWARE_PKI \
	"http://www.projectliberty.org/schemas/authctx/classes/SoftwarePKI"
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_TIME_SYNC_TOKEN \
	"http://www.projectliberty.org/schemas/authctx/classes/TimeSyncToken"

/* AuthnContextComparison */
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_EXACT	 "exact"
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MINIMUM	 "minimum"
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MAXIMUM	 "maximum"
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_BETTER	 "better"

/* StatusCodes */
#define LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST    "lib:FederationDoesNotExist"
#define LASSO_LIB_STATUS_CODE_INVALID_ASSERTION_CONSUMER_SERVICE_INDEX \
	"lib:InvalidAssertionConsumerServiceIndex"
#define LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE            "lib:InvalidSignature"
#define LASSO_LIB_STATUS_CODE_NO_AUTHN_CONTEXT             "lib:NoAuthnContext"
#define LASSO_LIB_STATUS_CODE_NO_AVAILABLEIDP              "lib:NoAvailableIDP"
#define LASSO_LIB_STATUS_CODE_NO_PASSIVE                   "lib:NoPassive"
#define LASSO_LIB_STATUS_CODE_NO_SUPPORTEDIDP              "lib:NoSupportedIDP"
#define LASSO_LIB_STATUS_CODE_PROXY_COUNT_EXCEEDED         "lib:ProxyCountExceeded"
#define LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL            "lib:UnknownPrincipal"
#define LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST       "lib:UnsignedAuthnRequest"
#define LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE          "lib:UnsupportedProfile"

/* ProtocolProfile */
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART	\
	"http://projectliberty.org/profiles/brws-art"
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST	\
	"http://projectliberty.org/profiles/brws-post"
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_LECP	\
	"http://projectliberty.org/profiles/lecp"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_HTTP	\
	"http://projectliberty.org/profiles/fedterm-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_SOAP	\
	"http://projectliberty.org/profiles/fedterm-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_HTTP	\
	"http://projectliberty.org/profiles/fedterm-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_SOAP	\
	"http://projectliberty.org/profiles/fedterm-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_NIM_SP_HTTP	\
	"http://projectliberty.org/profiles/nim-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_HTTP "http://projectliberty.org/profiles/rni-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_SOAP "http://projectliberty.org/profiles/rni-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_HTTP  "http://projectliberty.org/profiles/rni-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_SOAP  "http://projectliberty.org/profiles/rni-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_HTTP  "http://projectliberty.org/profiles/slo-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP  "http://projectliberty.org/profiles/slo-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_HTTP "http://projectliberty.org/profiles/slo-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_SOAP "http://projectliberty.org/profiles/slo-idp-soap"

/* NameIdentifier formats */
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED "urn:liberty:iff:nameid:federated"
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME  "urn:liberty:iff:nameid:one-time"
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENCRYPTED "urn:liberty:iff:nameid:encrypted"
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENTITYID  "urn:liberty:iff:nameid:entityID"

/* Consent */
#define LASSO_LIB_CONSENT_OBTAINED                  "urn:liberty:consent:obtained"
#define LASSO_LIB_CONSENT_OBTAINED_PRIOR            "urn:liberty:consent:obtained:prior"
#define LASSO_LIB_CONSENT_OBTAINED_CURRENT_IMPLICIT "urn:liberty:consent:obtained:current:implicit"
#define LASSO_LIB_CONSENT_OBTAINED_CURRENT_EXPLICIT "urn:liberty:consent:obtained:current:explicit"
#define LASSO_LIB_CONSENT_UNAVAILABLE               "urn:liberty:consent:unavailable"
#define LASSO_LIB_CONSENT_INAPPLICABLE              "urn:liberty:consent:inapplicable"

/*****************************************************************************/
/* Liberty Alliance ID-WSF                                                   */
/*****************************************************************************/

/* Liberty Security Mechanisms */
#define LASSO_SECURITY_MECH_NULL   "urn:liberty:security:2003-08:NULL:NULL"

#define LASSO_SECURITY_MECH_X509   "urn:liberty:security:2003-08:NULL:X509"
#define LASSO_SECURITY_MECH_SAML   "urn:liberty:security:2003-08:NULL:SAML"
#define LASSO_SECURITY_MECH_BEARER "urn:liberty:security:2004-04:NULL:Bearer"

#define LASSO_SECURITY_MECH_TLS        "urn:liberty:security:2003-08:TLS:null"
#define LASSO_SECURITY_MECH_TLS_X509   "urn:liberty:security:2003-08:TLS:X509"
#define LASSO_SECURITY_MECH_TLS_SAML   "urn:liberty:security:2003-08:TLS:SAML"
#define LASSO_SECURITY_MECH_TLS_BEARER "urn:liberty:security:2004-04:TLS:Bearer"

#define LASSO_SECURITY_MECH_CLIENT_TLS        "urn:liberty:security:2003-08:ClientTLS:null"
#define LASSO_SECURITY_MECH_CLIENT_TLS_X509   "urn:liberty:security:2003-08:ClientTLS:X509"
#define LASSO_SECURITY_MECH_CLIENT_TLS_SAML   "urn:liberty:security:2003-08:ClientTLS:SAML"
#define LASSO_SECURITY_MECH_CLIENT_TLS_BEARER "urn:liberty:security:2004-04:ClientTLS:Bearer"


/* liberty wsf prefix & href */
#define LASSO_DISCO_HREF   "urn:liberty:disco:2003-08"
#define LASSO_DISCO_PREFIX "disco"

#define LASSO_EP_HREF   "urn:liberty:id-sis-ep:2003-08"
#define LASSO_EP_PREFIX "ep"

#define LASSO_PP_HREF   "urn:liberty:id-sis-pp:2003-08"
#define LASSO_PP_PREFIX "pp"

#define LASSO_IS_HREF "urn:liberty:is:2003-08"
#define LASSO_IS_PREFIX "is"

#define LASSO_SA_HREF "urn:liberty:sa:2004-04"
#define LASSO_SA_PREFIX "sa"

#define LASSO_SEC_HREF "urn:liberty:sec:2003-08"
#define LASSO_SEC_PREFIX "sec"

#define LASSO_SA_SASL_SERVICE_NAME "idwsf"

/* Interaction Service (interact attribute of is:UserInteraction element ) */
#define LASSO_IS_INTERACT_ATTR_INTERACT_IF_NEEDED "is:interactIfNeeded"
#define LASSO_IS_INTERACT_ATTR_DO_NOT_INTERACT "is:doNotInteract"
#define LASSO_IS_INTERACT_ATTR_DO_NOT_INTERACT_FOR_DATA "is:doNotInteractForData"

/* status code */
#define LASSO_DISCO_STATUS_CODE_OK "OK"
#define LASSO_DISCO_STATUS_CODE_FAILED "Failed"
#define LASSO_DISCO_STATUS_CODE_REMOVE_ENTRY "RemoveEntry"
#define LASSO_DISCO_STATUS_CODE_FORBIDDEN "Forbidden"
#define LASSO_DISCO_STATUS_CODE_NO_RESULTS "NoResults"
#define LASSO_DISCO_STATUS_CODE_DIRECTIVES "Directive"

#define LASSO_DST_STATUS_CODE_ACTION_NOT_AUTHORIZED "ActionNotAuthorized"
#define LASSO_DST_STATUS_CODE_ACTION_NOT_SUPPORTED "ActionNotSupported"
#define LASSO_DST_STATUS_CODE_ALL_RETURNED "AllReturned"
#define LASSO_DST_STATUS_CODE_CHANGE_HISTORY_NOT_SUPPORTED "ChangeHistoryNotSupported"
#define LASSO_DST_STATUS_CODE_CHANGED_SINCE_RETURNS_ALL "ChangedSinceReturnsAll"
#define LASSO_DST_STATUS_CODE_DATA_TOO_LONG "DataTooLong"
#define LASSO_DST_STATUS_CODE_EXISTS_ALREADY "ExistsAlready"
#define LASSO_DST_STATUS_CODE_EXTENSION_NOT_SUPPORTED "ExtensionNotSupported"
#define LASSO_DST_STATUS_CODE_FAILED "Failed"
#define LASSO_DST_STATUS_CODE_INVALID_DATA "InvalidData"
#define LASSO_DST_STATUS_CODE_INVALID_RESOURCE_ID "InvalidResourceID"
#define LASSO_DST_STATUS_CODE_INVALID_SELECT "InvalidSelect"
#define LASSO_DST_STATUS_CODE_MISSING_NEW_DATA_ELEMENT "MissingNewDataElement"
#define LASSO_DST_STATUS_CODE_MISSING_RESOURCE_ID_ELEMENT "MissingResourceIDElement"
#define LASSO_DST_STATUS_CODE_MISSING_SELECT "MissingSelect"
#define LASSO_DST_STATUS_CODE_MODIFIED_SINCE "ModifiedSince"
#define LASSO_DST_STATUS_CODE_NO_MORE_ELEMENTS "NoMoreElements"
#define LASSO_DST_STATUS_CODE_NO_MULTIPLE_ALLOWED "NoMultipleAllowed"
#define LASSO_DST_STATUS_CODE_NO_MULTIPLE_RESOURCES "NoMultipleResources"
#define LASSO_DST_STATUS_CODE_OK "OK"
#define LASSO_DST_STATUS_CODE_TIME_OUT "TimeOut"
#define LASSO_DST_STATUS_CODE_UNEXPECTED_ERROR "UnexpectedError"

#define LASSO_SA_STATUS_CODE_CONTINUE "continue"
#define LASSO_SA_STATUS_CODE_ABORT "abort"
#define LASSO_SA_STATUS_CODE_OK "OK"

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
#define LASSO_SAML_AUTHENTICATION_METHOD_HARDWARE_TOKEN		\
	"urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define LASSO_SAML_AUTHENTICATION_METHOD_SMARTCARD_PKI  "urn:ietf:rfc:2246"
#define LASSO_SAML_AUTHENTICATION_METHOD_SOFTWARE_PKI   "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define LASSO_SAML_AUTHENTICATION_METHOD_PGP            "urn:oasis:names:tc:SAML:1.0:am:PGP"
#define LASSO_SAML_AUTHENTICATION_METHODS_PKI           "urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define LASSO_SAML_AUTHENTICATION_METHOD_XKMS           "urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define LASSO_SAML_AUTHENTICATION_METHOD_XMLD_SIG       "urn:ietf:rfc:3075"
#define LASSO_SAML_AUTHENTICATION_METHOD_UNSPECIFIED	\
	"urn:oasis:names:tc:SAML:1.0:am:unspecified"
#define LASSO_SAML_AUTHENTICATION_METHOD_LIBERTY        "urn:liberty:ac:2003-08"

/* ConfirmationMethods */
#define LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT "urn:oasis:names:tc:SAML:1.0:cm:artifact"
#define LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01 "urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
#define LASSO_SAML_CONFIRMATION_METHOD_BEARER "urn:oasis:names:tc:SAML:1.0:cm:bearer"
#define LASSO_SAML_CONFIRMATION_METHOD_HOLDER_OF_KEY	 \
	"urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
#define LASSO_SAML_CONFIRMATION_METHOD_SENDER_VOUCHES	 \
	"urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"

/*****************************************************************************/
/* SOAP BINDING                                                              */
/*****************************************************************************/

#define LASSO_SOAP_ENV_HREF   "http://schemas.xmlsoap.org/soap/envelope/"
#define LASSO_SOAP_ENV_PREFIX "s"

#define LASSO_SOAP_ENV_ACTOR "http://schemas.xmlsoap.org/soap/actor/next"

#define LASSO_SOAP_BINDING_HREF   "urn:liberty:sb:2003-08"
#define LASSO_SOAP_BINDING_PREFIX "sb"

#define LASSO_SOAP_BINDING_EXT_HREF "urn:liberty:sb:2004-04"
#define LASSO_SOAP_BINDING_EXT_PREFIX "sbe"

#define LASSO_WSSE_HREF "http://schemas.xmlsoap.org/ws/2002/07/secext"
#define LASSO_WSSE_PREFIX "wsse"

#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_OFFLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOffline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_ONLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOnline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_SIMULATE \
	"urn:liberty:sb:2003-08:ProcessingContext:Simulate"

/*****************************************************************************/
/* POAS BINDING                                                              */
/*****************************************************************************/

#define LASSO_POAS_HREF   "urn:liberty:paos:2003-08"
#define LASSO_POAS_PREFIX "poas"

/*****************************************************************************/
/* ECP BINDING                                                              */
/*****************************************************************************/

#define LASSO_ECP_HREF   "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
#define LASSO_ECP_PREFIX "ecp"

/*****************************************************************************/
/* SAML 2.0                                                                  */
/*****************************************************************************/

#define LASSO_SAML20_METADATA_HREF "urn:oasis:names:tc:SAML:2.0:metadata"

#define LASSO_SAML20_METADATA_BINDING_SOAP "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
#define LASSO_SAML20_METADATA_BINDING_REDIRECT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
#define LASSO_SAML20_METADATA_BINDING_POST "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
#define LASSO_SAML20_METADATA_BINDING_ARTIFACT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
#define LASSO_SAML20_METADATA_BINDING_PAOS "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

#define LASSO_SAML2_PROTOCOL_HREF "urn:oasis:names:tc:SAML:2.0:protocol"
#define LASSO_SAML2_PROTOCOL_PREFIX "samlp"

#define LASSO_SAML2_ASSERTION_HREF "urn:oasis:names:tc:SAML:2.0:assertion"
#define LASSO_SAML2_ASSERTION_PREFIX "saml"

#define LASSO_SAML2_DEFLATE_ENCODING "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"


/* Name Identifier Format */

/* note that SAML 2.0 can also use SAML 1.1 name identifier formats */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"


/* Consent */
#define LASSO_SAML2_CONSENT_OBTAINED "urn:oasis:names:tc:SAML:2.0:consent:obtained"
#define LASSO_SAML2_CONSENT_PRIOR "urn:oasis:names:tc:SAML:2.0:consent:prior"
#define LASSO_SAML2_CONSENT_IMPLICIT "urn:oasis:names:tc:SAML:2.0:consent:current-implicit"
#define LASSO_SAML2_CONSENT_EXPLICIT "urn:oasis:names:tc:SAML:2.0:consent:current-explicit"
#define LASSO_SAML2_CONSENT_UNAVAILABLE "urn:oasis:names:tc:SAML:2.0:consent:unavailable"
#define LASSO_SAML2_CONSENT_INAPPLICABLE "urn:oasis:names:tc:SAML:2.0:consent:inapplicable"

/* Status Code */
#define LASSO_SAML2_STATUS_CODE_SUCCESS "urn:oasis:names:tc:SAML:2.0:status:Success"
#define LASSO_SAML2_STATUS_CODE_REQUESTER "urn:oasis:names:tc:SAML:2.0:status:Requester"
#define LASSO_SAML2_STATUS_CODE_RESPONDER "urn:oasis:names:tc:SAML:2.0:status:Responder"
#define LASSO_SAML2_STATUS_CODE_VERSION_MISMATCH \
		"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
#define LASSO_SAML2_STATUS_CODE_AUTHN_FAILED "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
#define LASSO_SAML2_STATUS_CODE_INVALID_ATTR_NAME \
		"urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
#define LASSO_SAML2_STATUS_CODE_INVALID_NAME_ID_POLICY \
		"urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
#define LASSO_SAML2_STATUS_CODE_NO_AUTHN_CONTEXT \
		"urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
#define LASSO_SAML2_STATUS_CODE_NO_AVAILABLE_IDP \
		"urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"
#define LASSO_SAML2_STATUS_CODE_NO_PASSIVE \
		"urn:oasis:names:tc:SAML:2.0:status:NoPassive"
#define LASSO_SAML2_STATUS_CODE_NO_SUPPORTED_IDP \
		"urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"
#define LASSO_SAML2_STATUS_CODE_PARTIAL_LOGOUT \
		"urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
#define LASSO_SAML2_STATUS_CODE_PROXY_COUNT_EXCEEDED \
		"urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"
#define LASSO_SAML2_STATUS_CODE_REQUEST_DENIED \
		"urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
#define LASSO_SAML2_STATUS_CODE_REQUEST_UNSUPPORTED \
		"urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
#define LASSO_SAML2_STATUS_CODE_REQUEST_VERSION_DEPRECATED \
		"urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
#define LASSO_SAML2_STATUS_CODE_REQUEST_VERSION_TOO_HIGH \
		"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
#define LASSO_SAML2_STATUS_CODE_REQUEST_VERSION_TOO_LOW \
		"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"
#define LASSO_SAML2_STATUS_CODE_RESOURCE_NOT_RECOGNIZED \
		"urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
#define LASSO_SAML2_STATUS_CODE_TOO_MANY_RESPONSES \
		"urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"
#define LASSO_SAML2_STATUS_CODE_UNKNOWN_ATTR_PROFILE \
		"urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"
#define LASSO_SAML2_STATUS_CODE_UNKNOWN_PRINCIPAL \
		"urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
#define LASSO_SAML2_STATUS_CODE_UNSUPPORTED_BINDING \
		"urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"

/* AuthnClassRef */

#define LASSO_SAML2_AUTHN_CONTEXT_AUTHENTICATED_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"
#define LASSO_SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"
#define LASSO_SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL_PASSWORD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
#define LASSO_SAML2_AUTHN_CONTEXT_KERBEROS \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_CONTRACT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_UNREGISTERED \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_CONTRACT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_UNREGISTERED \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"
#define LASSO_SAML2_AUTHN_CONTEXT_NOMAD_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"
#define LASSO_SAML2_AUTHN_CONTEXT_PERSONALIZED_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalizedTelephony"
#define LASSO_SAML2_AUTHN_CONTEXT_PGP \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"
#define LASSO_SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
#define LASSO_SAML2_AUTHN_CONTEXT_PASSWORD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
#define LASSO_SAML2_AUTHN_CONTEXT_PREVIOUS_SESSION \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
#define LASSO_SAML2_AUTHN_CONTEXT_SMARTCARD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
#define LASSO_SAML2_AUTHN_CONTEXT_SMARTCARD_PKI \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
#define LASSO_SAML2_AUTHN_CONTEXT_SOFTWARE_PKI \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
#define LASSO_SAML2_AUTHN_CONTEXT_SPKI \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
#define LASSO_SAML2_AUTHN_CONTEXT_SECURE_REMOTE_PASSWORD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
#define LASSO_SAML2_AUTHN_CONTEXT_TLS_CLIENT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
#define LASSO_SAML2_AUTHN_CONTEXT_X509 \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
#define LASSO_SAML2_AUTHN_CONTEXT_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"
#define LASSO_SAML2_AUTHN_CONTEXT_TIME_SYNC_TOKEN \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
#define LASSO_SAML2_AUTHN_CONTEXT_XMLDSIG \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"

/* Confirmation methods */

#define LASSO_SAML2_CONFIRMATION_METHOD_BEARER "urn:oasis:names:tc:SAML:2.0:cm:bearer"

/*****************************************************************************/
/* Others                                                                    */
/*****************************************************************************/

/* xsi prefix & href */
#define LASSO_XSI_HREF "http://www.w3.org/2001/XMLSchema-instance"
#define LASSO_XSI_PREFIX "xsi"

#define LASSO_SOAP_FAULT_CODE_SERVER "Server"

#endif /* __LASSO_STRINGS_H__ */
