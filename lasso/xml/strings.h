/* $Id$
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
 * This header file copy part of the SOAP 1.1 specification you can found there:
 * http://www.w3.org/TR/soap12-part1/
 * whom copyright is:
 * Copyright © 2007 W3C® (MIT, ERCIM, Keio), All Rights Reserved. W3C liability, trademark and
 * document use rules apply.
 */


/**
 * SECTION:strings
 * @short_description: General strings constants for Lasso
 * @include: lasso/xml/strings.h
 *
 **/

#ifndef __LASSO_STRINGS_H__
#define __LASSO_STRINGS_H__

#include "saml-2.0/saml2_strings.h"
#include "dsig/strings.h"

/*****************************************************************************/
/* SOAP 1.1                                                                  */
/*****************************************************************************/
/**
 * LASSO_SOAP_ENV_HREF:
 *
 * Namespace for SOAP 1.1 messages
 *
 */
#define LASSO_SOAP_ENV_HREF   "http://schemas.xmlsoap.org/soap/envelope/"
/**
 * LASSO_SOAP_ENV_PREFIX:
 *
 * Preferred prefix for namespace of SOAP 1.1 messages
 *
 */
#define LASSO_SOAP_ENV_PREFIX "s"

#define LASSO_SOAP_ENV_ACTOR "http://schemas.xmlsoap.org/soap/actor/next"
/**
 * LASSO_SOAP_FAULT_CODE_SERVER:
 *
 * Quoting from SOAP 1.1 specifications:
 * « The Server class of errors indicate that the message could not be processed for reasons not
 * directly attributable to the contents of the message itself but rather to the processing of the
 * message. For example, processing could include communicating with an upstream processor, which
 * didn't respond. The message may succeed at a later point in time. See also section 4.4 for a
 * description of the SOAP Fault detail sub-element. »
 */
#define LASSO_SOAP_FAULT_CODE_SERVER "s:Server"

/**
 * LASSO_SOAP_FAULT_CODE_CLIENT:
 *
 * Quoting from SOAP 1.1 specifications:
 * « The Client class of errors indicate that the message was incorrectly formed or did not contain
 * the appropriate information in order to succeed. For example, the message could lack the proper
 * authentication or payment information. It is generally an indication that the message should not
 * be resent without change. See also section 4.4 for a description of the SOAP Fault detail
 * sub-element. »
 */
#define LASSO_SOAP_FAULT_CODE_CLIENT "s:Client"

/**
 * LASSO_SOAP_FAULT_CODE_MUST_UNDERSTAND:
 *
 * Quoting from SOAP 1.1 specifications:
 * « The processing party found an invalid namespace for the SOAP Envelope element (see section
 * 4.1.2) »
 */
#define LASSO_SOAP_FAULT_CODE_MUST_UNDERSTAND "s:MustUnderstand"

/**
 * LASSO_SOAP_FAULT_CODE_CLIENT:
 *
 * Quoting from SOAP 1.1 specifications:
 * « An immediate child element of the SOAP Header element that was either not understood or not
 * obeyed by the processing party contained a SOAP mustUnderstand attribute with a value of "1" (see
 * section 4.2.3) »
 */
#define LASSO_SOAP_FAULT_CODE_VERSION_MISMATCH "s:VersionMismatch"

/**
 * LASSO_PRIVATE_STATUS_CODE_FAILED_TO_RESTORE_ARTIFACT:
 *
 * An artifact content is present but Lasso failed to rebuild the corresponding XML content.
 */
#define LASSO_PRIVATE_STATUS_CODE_FAILED_TO_RESTORE_ARTIFACT "FailedToRestoreArtifact"

/*
 * WS-Security Utility
 */

/**
 * LASSO_WSUTIL1_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSUTIL1_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
/**
 * LASSO_WSUTIL1_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSUTIL1_PREFIX "wsutil"

/**
 * LASSO_XMLENC_HREF
 *
 * Namespace for xmlenc-core
 */
#define LASSO_XMLENC_HREF "http://www.w3.org/2001/04/xmlenc#"

/**
 * LASSO_XMLENC_PREFIX
 *
 * Preferred prefix for namespace of xmlenc-core
 */
#define LASSO_XMLENC_PREFIX "xmlenc"

/*****************************************************************************/
/* Lasso                                                                     */
/*****************************************************************************/

/**
 * LASSO_LASSO_HREF:
 *
 * Namespace for Lasso internal serialization format
 */
#define LASSO_LASSO_HREF   "http://www.entrouvert.org/namespaces/lasso/0.0"
/**
 * LASSO_LASSO_PREFIX:
 *
 * Preferred prefix for the lasso internal serialization format namespace.
 */
#define LASSO_LASSO_PREFIX "lasso"

/**
 * LASSO_PYHTON_HREF:
 *
 * Namespace for translation of Lasso symbols to the python namespace.
 */
#define LASSO_PYTHON_HREF "http://www.entrouvert.org/namespaces/python/0.0"

/**
 * LASSO_SIGNATURE_TYPE_ATTRIBUTE:
 *
 * Attribute name for the Lasso signature type attribute.
 */
#define LASSO_SIGNATURE_TYPE_ATTRIBUTE BAD_CAST "SignatureType"

/**
 * LASSO_SIGNATURE_METHOD_ATTRIBUTE:
 *
 * Attribute name for the Lasso signature type attribute.
 */
#define LASSO_SIGNATURE_METHOD_ATTRIBUTE BAD_CAST "SignatureMethod"

/**
 * LASSO_PRIVATE_KEY_ATTRIBUTE:
 *
 * Attribute name for the Lasso private key attribute.
 */
#define LASSO_PRIVATE_KEY_ATTRIBUTE BAD_CAST "PrivateKey"

/**
 * LASSO_PRIVATE_KEY_PASSWORD_ATTRIBUTE:
 *
 * Attribute name for the Lasso private key attribute.
 */
#define LASSO_PRIVATE_KEY_PASSWORD_ATTRIBUTE BAD_CAST "PrivateKeyPassword"

/**
 * LASSO_CERTIFICATE_ATTRIBUTE:
 *
 * Attribute name for the Lasso private key attribute.
 */
#define LASSO_CERTIFICATE_ATTRIBUTE BAD_CAST "Certificate"

/*****************************************************************************/
/* Liberty Alliance ID-FF                                                    */
/*****************************************************************************/

/**
 * LASSO_LIB_HREF:
 *
 * Namespace for the elements specific to ID-FF 1.2 (not part of SAML 1.0)
 */
#define LASSO_LIB_HREF	 "urn:liberty:iff:2003-08"
/**
 * LASSO_LIB_PREFIX:
 *
 * Preferred prefix for the ID-FF 1.2 namespace
 */
#define LASSO_LIB_PREFIX	 "lib"

/* Versioning */
/**
 * LASSO_LIB_MAJOR_VERSION_N:
 *
 * Major version of the ID-FF protocol supported.
 */
#define LASSO_LIB_MAJOR_VERSION_N	 1
/**
 * LASSO_LIB_MINOR_VERSION_N
 *
 * Minor version of the ID-FF protocol supported.
 */
#define LASSO_LIB_MINOR_VERSION_N	 2

/* NameIDPolicyType */

/**
 * LASSO_LIB_NAMEID_POLICY_TYPE_NONE:
 *
 * <emphasis>None</emphasis> policy for use in #LassoLibAuthnRequest.  It
 * means an existing federation must be used and an error should be produced if
 * none existed beforehand.
 */
#define LASSO_LIB_NAMEID_POLICY_TYPE_NONE	 "none"

/**
 * LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME:
 *
 * <emphasis>Onetime</emphasis> policy for use in #LassoLibAuthnRequest.  It
 * means a federation must not be created between identity and service
 * provider.  A temporary name identifier should be used instead.
 */
#define LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME	 "onetime"

/**
 * LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED:
 *
 * <emphasis>Federated</emphasis> policy for use in #LassoLibAuthnRequest.  It
 * means a federation may be created between identity and service provider (if
 * it didn't exist before).
 */
#define LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED	 "federated"

/**
 * LASSO_LIB_NAMEID_POLICY_TYPE_ANY:
 *
 * <emphasis>Any</emphasis> policy for use in #LassoLibAuthnRequest.  It means
 * a federation may be created if the principal agrees and it can fall back to
 * <emphasis>onetime</emphasis> if he does not.
 */
#define LASSO_LIB_NAMEID_POLICY_TYPE_ANY	 "any"

/* AuthenticationClassRef */
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_INTERNET_PROTOCOL:
 *
 * The Internet Protocol class is identified when a Principal is authenticated through the use of a
 * provided IP address.
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_INTERNET_PROTOCOL \
	"http://www.projectliberty.org/schemas/authctx/classes/InternetProtocol"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_INTERNET_PROTOCOL_PASSWORD:
 *
 * The Internet Protocol Password class is identified when a Principal is authenticated through the
 * use of a provided IP address, in addition to username/password.
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_INTERNET_PROTOCOL_PASSWORD \
	"http://www.projectliberty.org/schemas/authctx/classes/InternetProtocolPassword"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_UNREGISTERED:
 *
 * Reflects no mobile customer registration procedures and an authentication of the mobile device
 * without requiring explicit end-user interaction. Again, this context authenticates only the
 * device and never the user, it is useful when services other than the mobile operator want to add
 * a secure device authentication to their authentication process.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_UNREGISTERED \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileOneFactorUnregistered"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_UNREGISTERED:
 *
 * Reflects no mobile customer registration procedures and a two-factor based authentication, such
 * as secure device and user PIN. This context class is useful when a service other than the mobile
 * operator wants to link their customer ID to a mobile supplied two-factor authentication service
 * by capturing mobile phone data at enrollment.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_UNREGISTERED \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileTwoFactorUnregistered"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_CONTRACT:
 *
 * Reflects mobile contract customer registration procedures and a single factor authentication. For
 * example, a digital signing device with tamper resistant memory for key storage, such as the
 * mobile MSISDN, but no required PIN or biometric for real-time user authentication.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_ONE_FACTOR_CONTRACT \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileOneFactorContract"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_CONTRACT:
 *
 * Reflects mobile contract customer registration procedures and a two-factor based authentication.
 * For example, a digital signing device with tamper resistant memory for key storage, such as a GSM
 * SIM, that requires explicit proof of user identity and intent, such as a PIN or biometric.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_MOBILE_TWO_FACTOR_CONTRACT \
	"http://www.projectliberty.org/schemas/authctx/classes/MobileTwoFactorContract"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD:
 *
 * The Password class is identified when a Principal authenticates to an identity provider through
 * the presentation of a password over an unprotected HTTP session.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD \
	"http://www.projectliberty.org/schemas/authctx/classes/Password"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD_PROTECTED_TRANSPORT:
 *
 * The PasswordProtectedTransport class is identified when a Principal authenticates to an identity
 * provider through the presentation of a password over a protected session.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PASSWORD_PROTECTED_TRANSPORT \
	"http://www.projectliberty.org/schemas/authctx/classes/PasswordProtectedTransport"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PREVIOUS_SESSION:
 *
 * The PreviousSession class is identified when a Principal had authenticated to an identity
 * provider at some point in the past using any authentication context supported by that identity
 * provider. Consequently, a subsequent authentication event that the identity provider will assert
 * to the service provider may be significantly separated in time from the Principals current
 * resource access request.  The context for the previously authenticated session is explicitly not
 * included in this context class because the user has not authenticated during this session, and so
 * the mechanism that the user employed to authenticate in a previous session should not be used as
 * part of a decision on whether to now allow access to a resource.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_PREVIOUS_SESSION \
	"http://www.projectliberty.org/schemas/authctx/classes/PreviousSession"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SMARTCARD:
 *
 * The Smartcard class is identified when a Principal authenticates to an identity provider using a
 * smartcard.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SMARTCARD \
	"http://www.projectliberty.org/schemas/authctx/classes/Smartcard"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SMARTCARD_PKI:
 *
 * The SmartcardPKI class is identified when a Principal authenticates to an identity provider
 * through a two-factor
 authentication mechanism using a smartcard with enclosed private key and a PIN.

 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SMARTCARD_PKI \
	"http://www.projectliberty.org/schemas/authctx/classes/SmartcardPKI"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SOFTWARE_PKI:
 *
 * The Software-PKI class is identified when a Principal uses an X.509 certificate stored in
 * software to authenticate to the identity provider.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_SOFTWARE_PKI \
	"http://www.projectliberty.org/schemas/authctx/classes/SoftwarePKI"
/**
 * LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_TIME_SYNC_TOKEN:

 * The TimeSyncToken class is identified when a Principal authenticates through a time
 * synchronization token.
 *
 * Source: Liberty ID-FF Authentication Context Specification v1.3
 */
#define LASSO_LIB_AUTHN_CONTEXT_CLASS_REF_TIME_SYNC_TOKEN \
	"http://www.projectliberty.org/schemas/authctx/classes/TimeSyncToken"

/* AuthnContextComparison */
/**
 * LASSO_LIB_AUTHN_CONTEXT_COMPARISON_EXACT:
 *
 * Ask for the exact authentication context.
 */
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_EXACT	 "exact"
/**
 * LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MINIMUM:
 *
 * Ask for at least this authentication context.
 */
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MINIMUM	 "minimum"
/**
 * LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MAXIMUM:
 *
 * Ask for at most this authentication context.
 */
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_MAXIMUM	 "maximum"
/**
 * LASSO_LIB_AUTHN_CONTEXT_COMPARISON_BETTER	:
 *
 * Ask for a better authentication context than that.
 */
#define LASSO_LIB_AUTHN_CONTEXT_COMPARISON_BETTER	 "better"

/* StatusCodes */
/**
 * LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST:
 *
 * <para>Second level status code.</para>
 *
 * Used by an identity provider to indicate that the Principal has not federated his or her identity
 * with the service provider, and the service provider indicated a requirement for
 federation.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST    "lib:FederationDoesNotExist"
/**
 * LASSO_LIB_STATUS_CODE_INVALID_ASSERTION_CONSUMER_SERVICE_INDEX:
 *
 * <para>Second level status code.</para>
 *
 * If the &lt;AssertionConsumerServiceID&gt; element is provided, then the identity provider <emphasis>MUST</emphasis> search
 * for the value among the id attributes in the &lt;AssertionConsumerServiceURL&gt; elements in the
 * provider’s meta- data to determine the URL to use. If no match can be found, then the provider
 * <emphasis>MUST</emphasis> return an error with a second-level &lt;samlp:StatusCode&gt; of
 * lib:InvalidAssertionConsumerServiceIndex to the default URL (the &lt;AssertionConsumerServiceURL&gt;
 * with an isDefault attribute of "true").
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_INVALID_ASSERTION_CONSUMER_SERVICE_INDEX \
	"lib:InvalidAssertionConsumerServiceIndex"
/**
 * LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE:
 *
 * <para>Second level status code.</para>
 *
 * Indicate a failure in the processing of the signature of the request.
 * This code is not part of the ID-FF 1.2 specification.
 *
 */
#define LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE            "lib:InvalidSignature"
/**
 * LASSO_LIB_STATUS_CODE_NO_AUTHN_CONTEXT:
 *
 * Used by an identity provider to indicate that the specified authentication context information in
 * the request prohibits authentication from taking place.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_NO_AUTHN_CONTEXT             "lib:NoAuthnContext"
/**
 * LASSO_LIB_STATUS_CODE_NO_AVAILABLEIDP:
 *
 * Used by an intermediary to indicate that none of the supported identity provider URLs from the
 * &lt;IDPList&gt; can be resolved or that none of the supported identity providers are available.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_NO_AVAILABLEIDP              "lib:NoAvailableIDP"
/**
 * LASSO_LIB_STATUS_CODE_NO_PASSIVE:
 *
 * Used by an identity provider or an intermediary to indicate that authentication of the Principal
 * requires interaction and cannot be performed passively.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_NO_PASSIVE                   "lib:NoPassive"
/**
 * LASSO_LIB_STATUS_CODE_NO_SUPPORTEDIDP             :
 *
 * Used by an intermediary to indicate that none of the identity providers are supported by the
 * intermediary.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_NO_SUPPORTEDIDP              "lib:NoSupportedIDP"
/**
 * LASSO_LIB_STATUS_CODE_PROXY_COUNT_EXCEEDED        :
 *
 * Used by an identity provider to indicate that it cannot authenticate the principal itself, and
 * was not permitted to relay the request further.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_PROXY_COUNT_EXCEEDED         "lib:ProxyCountExceeded"
/**
 * LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL           :
 *
 * Used by an identity provider to indicate that the Principal is not known to it.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_UNKNOWN_PRINCIPAL            "lib:UnknownPrincipal"
/**
 * LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST      :
 *
 * If the requesting provider’s &lt;AuthnRequestsSigned&gt; metadata element is "true", then any request
 * messages it generates <emphasis>MUST</emphasis> be signed. If an unsigned request is received, then the provider <emphasis>MUST</emphasis>
 * return an error with a second- level &lt;samlp:StatusCode&gt; of lib:UnsignedAuthnRequest.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_UNSIGNED_AUTHN_REQUEST       "lib:UnsignedAuthnRequest"
/**
 * LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE         :
 *
 * If an error occurs during this further processing of the logout (for example, relying service
 * providers may not all implement the Single Logout profile used by the requesting service
 * provider), then the identity provider <emphasis>MUST</emphasis> respond to the original requester with a
 * &lt;LogoutResponse&gt; message, indicating the status of the logout request. The value
 * "lib:UnsupportedProfile" is provided for a second-level &lt;samlp:StatusCode&gt;, indicating that a
 * service provider should retry the &lt;LogoutRequest&gt; using a different profile.
 *
 * Source: Liberty ID-FF Protocols and Schema Specification 1.2
 */
#define LASSO_LIB_STATUS_CODE_UNSUPPORTED_PROFILE          "lib:UnsupportedProfile"

/* ProtocolProfile */

/**
 * LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART:
 *
 * Identifies the Single Sign-On "Artifact" profile; where an artifact is
 * passed from identity provider to service provider and back to get the
 * #LassoLibAssertion.
 */
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART	\
	"http://projectliberty.org/profiles/brws-art"

/**
 * LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST:
 *
 * Identifies the Single Sign-On "POST" profile; where the #LassoLibAssertion
 * is sent directly from the identity provider to the service provider in an
 * HTML form submission message.
 */
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST	\
	"http://projectliberty.org/profiles/brws-post"

/**
 * LASSO_LIB_PROTOCOL_PROFILE_BRWS_LECP:
 *
 * Identifies the Single Sign-On "LECP" profile; where the #LassoLibAssertion
 * is sent directly from the identity provider to the service provider in a
 * PAOS response. See #LassoLecp.
 *
 */
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_LECP	\
	"http://projectliberty.org/profiles/lecp"
/**
 * LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_HTTP:
 *
 * Identifies the Federation Termination "Redirect" profile; where the request for federation
 * termination is sent from the identity provider to the service provider in a redirected GET request.
 *
 */
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

/**
 * LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED:
 *
 * <emphasis>Federated</emphasis> name identifier constant, used in
 * #LassoSamlNameIdentifier.  It implies the name identifier belongs to
 * a federation established between SP and IdP.
 */
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED "urn:liberty:iff:nameid:federated"

/**
 * LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME:
 *
 * "One-time" name identifier constant, used in #LassoSamlNameIdentifier.
 */
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME  "urn:liberty:iff:nameid:one-time"

/**
 * LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENCRYPTED:
 *
 * "Encrypted" name identifier constant, used in #LassoSamlNameIdentifier.
 */
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
/* METADATA                                                                  */
/*****************************************************************************/

/* prefix & href */
/**
 * LASSO_METADATA_HREF:
 *
 * Namespace for ID-FF 1.2 metadatas.
 *
 */
#define LASSO_METADATA_HREF	 "urn:liberty:metadata:2003-08"
/**
 * LASSO_METADATA_PREFIX:
 *
 * Preferred prefix for ID-FF 1.2 metadata namespace.
 */
#define LASSO_METADATA_PREFIX	 "md"

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
/**
 * LASSO_SAML_ASSERTION_HREF:
 *
 * Namespace for SAML 1.0 assertion elements.
 */
#define LASSO_SAML_ASSERTION_HREF	"urn:oasis:names:tc:SAML:1.0:assertion"
/**
 * LASSO_SAML_ASSERTION_PREFIX:
 *
 * Preferred prefix for assertion elements.
 */
#define LASSO_SAML_ASSERTION_PREFIX	"saml"
/**
 * LASSO_SAML_PROTOCOL_HREF:
 *
 * Namespace for SAML 1.0 protocol elements.
 */
#define LASSO_SAML_PROTOCOL_HREF	"urn:oasis:names:tc:SAML:1.0:protocol"
/**
 * LASSO_SAML_PROTOCOL_PREFIX:
 *
 * Preferred prefix for assertion elements.
 */
#define LASSO_SAML_PROTOCOL_PREFIX	"samlp"

/* Versioning */
/**
 * LASSO_SAML_MAJOR_VERSION_N:
 *
 * Major version number of the SAML specification used for ID-FF support in Lasso.
 */
#define LASSO_SAML_MAJOR_VERSION_N	 1
/**
 * LASSO_SAML_MINOR_VERSION_N:
 *
 * Minor version number of the SAML specification used for ID-FF support in Lasso.
 */
#define LASSO_SAML_MINOR_VERSION_N	 1

/* First level StatusCodes */

/**
 * LASSO_SAML_STATUS_CODE_SUCCESS:
 *
 * A protocol request succeeded.
 */
#define LASSO_SAML_STATUS_CODE_SUCCESS	            "samlp:Success"
/**
 * LASSO_SAML_STATUS_CODE_VERSION_MISMATCH:
 *
 * Request failed, because the version is not supported by the provider. Look at second level status
 * for more details.
 */
#define LASSO_SAML_STATUS_CODE_VERSION_MISMATCH          "samlp:VersionMismatch"
/**
 * LASSO_SAML_STATUS_CODE_REQUESTER:
 *
 * Request failed because of the requester. Look at second level status for more details.
 */
#define LASSO_SAML_STATUS_CODE_REQUESTER                "samlp:Requester"
/**
 * LASSO_SAML_STATUS_CODE_RESPONDER:
 *
 * Request failed because of the responder. Look at second level status for more details.
 */
#define LASSO_SAML_STATUS_CODE_RESPONDER                "samlp:Responder"

/* Second level status codes */
/**
 * LASSO_SAML_STATUS_CODE_REQUEST_VERSION_TOO_HIGH:
 *
 * Request failed because the version of protocol used is too high.
 * Used with #LASSO_SAML_STATUS_CODE_VERSION_MISMATCH.
 */
#define LASSO_SAML_STATUS_CODE_REQUEST_VERSION_TOO_HIGH    "samlp:RequestVersionTooHigh"
/**
 * LASSO_SAML_STATUS_CODE_REQUEST_VERSION_TOO_LOW:
 *
 * Request failed because the version of protocol used is too low.
 * Used with #LASSO_SAML_STATUS_CODE_VERSION_MISMATCH.
 */
#define LASSO_SAML_STATUS_CODE_REQUEST_VERSION_TOO_LOW     "samlp:RequestVersionTooLow"
/**
 * LASSO_SAML_STATUS_CODE_REQUEST_VERSION_DEPRECATED:
 *
 * Request failed because the version of protocol used is deprecated.
 * Used with #LASSO_SAML_STATUS_CODE_VERSION_MISMATCH.
 */
#define LASSO_SAML_STATUS_CODE_REQUEST_VERSION_DEPRECATED "samlp:RequestVersionDeprecated"
/**
 * LASSO_SAML_STATUS_CODE_TOO_MANY_RESPONSES:
 *
 * Request failed because too many data should be returned.
 * Used with #LASSO_SAML_STATUS_CODE_RESPONDER.
 */
#define LASSO_SAML_STATUS_CODE_TOO_MANY_RESPONSES         "samlp:TooManyResponses"
/**
 * LASSO_SAML_STATUS_CODE_RESOURCE_NOT_RECOGNIZED:
 *
 * Request failed because the responder does not wish to support resource-specific attribute
 * queries, or the resource value provided is invalid or unrecognized.
 * Use with #LASSO_SAML_STATUS_CODE_RESPONDER.
 */
#define LASSO_SAML_STATUS_CODE_RESOURCE_NOT_RECOGNIZED    "samlp:ResourceNotRecognized"
/**
 * LASSO_SAML_STATUS_CODE_REQUEST_DENIED:
 *
 * The SAML responder or SAML authority is able to process the request but has chosen not to
 * respond. This status code MAY be used when there is concern about the security context of the
 * request message or the sequence of request messages received from a particular requester.
 *
 * Source: Assertions and Protocol for the OASIS  Security Assertion Markup Language (SAML) V1.1
 *
 */
#define LASSO_SAML_STATUS_CODE_REQUEST_DENIED            "samlp:RequestDenied"

/* AuthenticationMethods */
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD:
 *
 * The authentication was performed by means of a password.
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD	 "urn:oasis:names:tc:SAML:1.0:am:password"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_KERBEROS:
 *
 * The authentication was performed by means of the Kerberos protocol [RFC 1510], an instantiation
 * of the Needham-Schroeder symmetric key authentication mechanism [Needham78].
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_KERBEROS	 "urn:ietf:rfc:1510"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_SECURE_REMOTE_PASSWORD:
 *
 * The authentication was performed by means of Secure Remote Password protocol as specified in [RFC
 * 2945].
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_SECURE_REMOTE_PASSWORD	 "urn:ietf:rfc:2945"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_HARDWARE_TOKEN:
 *
 * The authentication was performed using some (unspecified) hardware token.
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_HARDWARE_TOKEN		\
	"urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_SMARTCARD_PKI:
 *
 * The authentication was performed using either the SSL or TLS protocol with certificate-based
 * client authentication. TLS is described in [RFC 2246].
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_SMARTCARD_PKI  "urn:ietf:rfc:2246"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_SOFTWARE_PKI:
 *
 * The authentication was performed by some (unspecified) mechanism on a key authenticated by means
 * of an X.509 PKI [X.500][PKIX]. It may have been one of the mechanisms for which a more specific
 * identifier has been defined below.
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_SOFTWARE_PKI   "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_PGP:
 *
 * The authentication was performed by some (unspecified) mechanism on a key authenticated by means
 * of a PGP web of trust [PGP]. It may have been one of the mechanisms for which a more specific
 * identifier has been defined below.
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_PGP            "urn:oasis:names:tc:SAML:1.0:am:PGP"
/**
 * LASSO_SAML_AUTHENTICATION_METHODS_PKI:
 *
 * The authentication was performed by some (unspecified) mechanism on a key authenticated by means
 * of a PGP web of trust [PGP]. It may have been one of the mechanisms for which a more specific
 * identifier has been defined below.
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHODS_PKI           "urn:oasis:names:tc:SAML:1.0:am:SPKI"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_XKMS:
 *
 * The authentication was performed by some (unspecified) mechanism on a key authenticated by means
 * of a PGP web of trust [PGP]. It may have been one of the mechanisms for which a more specific
 * identifier has been defined below.
 *
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_XKMS           "urn:oasis:names:tc:SAML:1.0:am:XKMS"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_XMLD_SIG:
 *
 * The authentication was performed by means of an XML digital signature [RFC 3075].
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_XMLD_SIG       "urn:ietf:rfc:3075"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_UNSPECIFIED:
 *
 * The authentication was performed by an unspecified means.
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_UNSPECIFIED	\
	"urn:oasis:names:tc:SAML:1.0:am:unspecified"
/**
 * LASSO_SAML_AUTHENTICATION_METHOD_LIBERTY:
 *
 *
 * The authentication was performed by a liberty alliance protocol.
 */
#define LASSO_SAML_AUTHENTICATION_METHOD_LIBERTY        "urn:liberty:ac:2003-08"

/* ConfirmationMethods */
/**
 * LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT:
 *
 * Confirmation method when the browser-artifact binding is used.
 */
#define LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT "urn:oasis:names:tc:SAML:1.0:cm:artifact"
/**
 * LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01:
 *
 *
 * Deprecated confirmation method when the browser-artifact binding is used.
 */
#define LASSO_SAML_CONFIRMATION_METHOD_ARTIFACT01 "urn:oasis:names:tc:SAML:1.0:cm:artifact-01"
/**
 * LASSO_SAML_CONFIRMATION_METHOD_BEARER:
 *
 * Confirmation method when subject of the assertion is the one holding it.
 */
#define LASSO_SAML_CONFIRMATION_METHOD_BEARER "urn:oasis:names:tc:SAML:1.0:cm:bearer"
/**
 * LASSO_SAML_CONFIRMATION_METHOD_HOLDER_OF_KEY:
 *
 * A ds:KeyInfo must be present in the SubjecConfirmation element. It <emphasis>MUST</emphasis> be
 * used to confirm assertion subject identity.
 */
#define LASSO_SAML_CONFIRMATION_METHOD_HOLDER_OF_KEY	 \
	"urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
/**
 * LASSO_SAML_CONFIRMATION_METHOD_SENDER_VOUCHES:
 *
 * Indicates that no other information is available about the context of use of the assertion. The
 * relying party
 * <emphasis>SHOULD</emphasis> utilize other means to determine if it should process the assertion further.
 *
 */
#define LASSO_SAML_CONFIRMATION_METHOD_SENDER_VOUCHES	 \
	"urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"

/*****************************************************************************/
/* POAS BINDING                                                              */
/*****************************************************************************/

/**
 * LASSO_PAOS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_PAOS_HREF   "urn:liberty:paos:2003-08"
/**
 * LASSO_PAOS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_PAOS_PREFIX "paos"

/*****************************************************************************/
/* ECP BINDING                                                              */
/*****************************************************************************/

/**
 * LASSO_ECP_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_ECP_HREF   "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
/**
 * LASSO_ECP_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_ECP_PREFIX "ecp"

/*****************************************************************************/
/* Others                                                                    */
/*****************************************************************************/

/* xsi prefix & href */
/**
 * LASSO_XSI_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_XSI_HREF "http://www.w3.org/2001/XMLSchema-instance"
/**
 * LASSO_XSI_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_XSI_PREFIX "xsi"

#endif /* __LASSO_STRINGS_H__ */

