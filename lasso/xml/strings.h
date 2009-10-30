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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * SECTION:strings
 * @short_description: Useful string constants
 *
 **/

#ifndef __LASSO_STRINGS_H__
#define __LASSO_STRINGS_H__

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
 * #LassoNameIdentifier.  It implies the name identifier belongs to
 * a federation established between SP and IdP.
 */
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED "urn:liberty:iff:nameid:federated"

/**
 * LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME:
 *
 * "One-time" name identifier constant, used in #LassoNameIdentifier.
 */
#define LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME  "urn:liberty:iff:nameid:one-time"

/**
 * LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENCRYPTED:
 *
 * "Encrypted" name identifier constant, used in #LassoNameIdentifier.
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
/* Liberty Alliance ID-WSF                                                   */
/*****************************************************************************/

/* Liberty Security Mechanisms - 1st version */
#define LASSO_SECURITY_MECH_NULL   "urn:liberty:security:2003-08:null:null"

#define LASSO_SECURITY_MECH_X509   "urn:liberty:security:2003-08:null:X509"
#define LASSO_SECURITY_MECH_SAML   "urn:liberty:security:2003-08:null:SAML"
#define LASSO_SECURITY_MECH_BEARER "urn:liberty:security:2004-04:null:Bearer"

#define LASSO_SECURITY_MECH_TLS        "urn:liberty:security:2003-08:TLS:null"
#define LASSO_SECURITY_MECH_TLS_X509   "urn:liberty:security:2003-08:TLS:X509"
#define LASSO_SECURITY_MECH_TLS_SAML   "urn:liberty:security:2003-08:TLS:SAML"
#define LASSO_SECURITY_MECH_TLS_BEARER "urn:liberty:security:2004-04:TLS:Bearer"

#define LASSO_SECURITY_MECH_CLIENT_TLS        "urn:liberty:security:2003-08:ClientTLS:null"
#define LASSO_SECURITY_MECH_CLIENT_TLS_X509   "urn:liberty:security:2003-08:ClientTLS:X509"
#define LASSO_SECURITY_MECH_CLIENT_TLS_SAML   "urn:liberty:security:2003-08:ClientTLS:SAML"
#define LASSO_SECURITY_MECH_CLIENT_TLS_BEARER "urn:liberty:security:2004-04:ClientTLS:Bearer"

/* Liberty Security Mechanisms - latest version */

#define LASSO_SECURITY11_MECH_X509   "urn:liberty:security:2005-02:null:X509"
#define LASSO_SECURITY11_MECH_SAML   "urn:liberty:security:2005-02:null:SAML"
#define LASSO_SECURITY11_MECH_BEARER "urn:liberty:security:2005-02:null:Bearer"

#define LASSO_SECURITY11_MECH_TLS_X509   "urn:liberty:security:2005-02:TLS:X509"
#define LASSO_SECURITY11_MECH_TLS_SAML   "urn:liberty:security:2005-02:TLS:SAML"
#define LASSO_SECURITY11_MECH_TLS_BEARER "urn:liberty:security:2005-02:TLS:Bearer"

/* liberty wsf prefix & href */
/**
 * LASSO_DISCO_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_DISCO_HREF          "urn:liberty:disco:2003-08"
/**
 * LASSO_DISCO_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_DISCO_PREFIX        "disco"

/**
 * LASSO_EP_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_EP_HREF   "urn:liberty:id-sis-ep:2003-08"
/**
 * LASSO_EP_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_EP_PREFIX "ep"

/**
 * LASSO_PP_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_PP_HREF   "urn:liberty:id-sis-pp:2003-08"
/**
 * LASSO_PP_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_PP_PREFIX "pp"

/**
 * LASSO_IS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IS_HREF "urn:liberty:is:2003-08"
/**
 * LASSO_IS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IS_PREFIX "is"

/**
 * LASSO_SA_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SA_HREF "urn:liberty:sa:2004-04"
/**
 * LASSO_SA_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SA_PREFIX "sa"

/**
 * LASSO_SEC_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SEC_HREF "urn:liberty:sec:2003-08"
/**
 * LASSO_SEC_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SEC_PREFIX "sec"

#define LASSO_SA_SASL_SERVICE_NAME "idwsf"

/* Interaction Service (interact attribute of is:UserInteraction element ) */
#define LASSO_IS_INTERACT_ATTR_INTERACT_IF_NEEDED "is:interactIfNeeded"
#define LASSO_IS_INTERACT_ATTR_DO_NOT_INTERACT "is:doNotInteract"
#define LASSO_IS_INTERACT_ATTR_DO_NOT_INTERACT_FOR_DATA "is:doNotInteractForData"

/* status code */
#define LASSO_DISCO_STATUS_CODE_OK "OK"
#define LASSO_DISCO_STATUS_CODE_DISCO_OK "disco:OK"
#define LASSO_DISCO_STATUS_CODE_FAILED "Failed"
#define LASSO_DISCO_STATUS_CODE_REMOVE_ENTRY "RemoveEntry"
#define LASSO_DISCO_STATUS_CODE_FORBIDDEN "Forbidden"
#define LASSO_DISCO_STATUS_CODE_NO_RESULTS "NoResults"
#define LASSO_DISCO_STATUS_CODE_DIRECTIVES "Directive"

#define LASSO_DST_STATUS_CODE_OK "OK"
#define LASSO_DST_STATUS_CODE_FAILED "Failed"
#define LASSO_DST_STATUS_CODE_PARTIAL "Partial"
#define LASSO_DST_STATUS_CODE_ACTION_NOT_AUTHORIZED "ActionNotAuthorized"
#define LASSO_DST_STATUS_CODE_ACTION_NOT_SUPPORTED "ActionNotSupported"
#define LASSO_DST_STATUS_CODE_ALL_RETURNED "AllReturned"
#define LASSO_DST_STATUS_CODE_CHANGE_HISTORY_NOT_SUPPORTED "ChangeHistoryNotSupported"
#define LASSO_DST_STATUS_CODE_CHANGED_SINCE_RETURNS_ALL "ChangedSinceReturnsAll"
#define LASSO_DST_STATUS_CODE_DATA_TOO_LONG "DataTooLong"
#define LASSO_DST_STATUS_CODE_EXISTS_ALREADY "ExistsAlready"
#define LASSO_DST_STATUS_CODE_EXTENSION_NOT_SUPPORTED "ExtensionNotSupported"
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
#define LASSO_DST_STATUS_CODE_TIME_OUT "TimeOut"
#define LASSO_DST_STATUS_CODE_UNEXPECTED_ERROR "UnexpectedError"

#define LASSO_SA_STATUS_CODE_OK "OK"
#define LASSO_SA_STATUS_CODE_CONTINUE "continue"
#define LASSO_SA_STATUS_CODE_ABORT "abort"

/*****************************************************************************/
/* METADATA                                                                  */
/*****************************************************************************/

/* prefix & href */
/**
 * LASSO_METADATA_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_METADATA_HREF	 "urn:liberty:metadata:2003-08"
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
/* SOAP BINDING                                                              */
/*****************************************************************************/

/**
 * LASSO_SOAP_ENV_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SOAP_ENV_HREF   "http://schemas.xmlsoap.org/soap/envelope/"
/**
 * LASSO_SOAP_ENV_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SOAP_ENV_PREFIX "s"

#define LASSO_SOAP_ENV_ACTOR "http://schemas.xmlsoap.org/soap/actor/next"

/**
 * LASSO_SOAP_BINDING_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SOAP_BINDING_HREF          "urn:liberty:sb:2003-08"
/**
 * LASSO_SOAP_BINDING_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SOAP_BINDING_PREFIX        "sb"

/**
 * LASSO_SOAP_BINDING_EXT_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SOAP_BINDING_EXT_HREF "urn:liberty:sb:2004-04"
/**
 * LASSO_SOAP_BINDING_EXT_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SOAP_BINDING_EXT_PREFIX "sbe"

/**
 * LASSO_IDWSF2_SB2_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SB2_HREF "urn:liberty:sb:2006-08"
/**
 * LASSO_IDWSF2_SB2_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SB2_PREFIX "sb"

/**
 * LASSO_IDWSF2_SBF_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SBF_HREF "urn:liberty:sb"
/**
 * LASSO_IDWSF2_SBF_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SBF_PREFIX "sbf"

#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_OFFLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOffline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_ONLINE \
	"urn:liberty:sb:2003-08:ProcessingContext:PrincipalOnline"
#define LASSO_SOAP_BINDING_PROCESS_CONTEXT_SIMULATE \
	"urn:liberty:sb:2003-08:ProcessingContext:Simulate"

#define LASSO_SOAP_FAULT_CODE_SERVER "S:server"

#define LASSO_SOAP_FAULT_CODE_CLIENT "Client"

#define LASSO_SOAP_FAULT_STRING_SERVER "Server Error"
#define LASSO_SOAP_FAULT_STRING_IDENTITY_NOT_FOUND "Identity not found"

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
/* SAML 2.0                                                                  */
/*****************************************************************************/

/**
 * LASSO_SAML2_METADATA_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SAML2_METADATA_HREF "urn:oasis:names:tc:SAML:2.0:metadata"

#define LASSO_SAML2_METADATA_BINDING_SOAP "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
#define LASSO_SAML2_METADATA_BINDING_REDIRECT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
#define LASSO_SAML2_METADATA_BINDING_POST "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
#define LASSO_SAML2_METADATA_BINDING_ARTIFACT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
#define LASSO_SAML2_METADATA_BINDING_PAOS "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

/**
 * LASSO_SAML2_PROTOCOL_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SAML2_PROTOCOL_HREF "urn:oasis:names:tc:SAML:2.0:protocol"
/**
 * LASSO_SAML2_PROTOCOL_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SAML2_PROTOCOL_PREFIX "samlp"

/**
 * LASSO_SAML2_ASSERTION_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_SAML2_ASSERTION_HREF "urn:oasis:names:tc:SAML:2.0:assertion"
/**
 * LASSO_SAML2_ASSERTION_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_SAML2_ASSERTION_PREFIX "saml"

#define LASSO_SAML2_DEFLATE_ENCODING "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"


/* Name Identifier Format */

/* note that SAML 2.0 can also use SAML 1.1 name identifier formats */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_X509 \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_WINDOWS \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

/* Attribute Name */
#define LASSO_SAML2_ATTRIBUTE_NAME_EPR "urn:liberty:disco:2006-08:DiscoveryEPR"

/* Attribute Name Format */
#define LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

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
#define LASSO_SAML2_AUTHN_CONTEXT_UNSPECIFIED \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"


/* Confirmation methods */

#define LASSO_SAML2_CONFIRMATION_METHOD_BEARER "urn:oasis:names:tc:SAML:2.0:cm:bearer"

/*****************************************************************************/
/* ID-WSF 2.0                                                                */
/*****************************************************************************/

/**
 * LASSO_IDWSF2_DISCO_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_DISCO_HREF   "urn:liberty:disco:2006-08"
/**
 * LASSO_IDWSF2_DISCO_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_DISCO_PREFIX "disco"

/**
 * LASSO_IDWSF2_DST_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_DST_HREF "urn:liberty:dst:2006-08"
/**
 * LASSO_IDWSF2_DST_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_DST_PREFIX "dst"

/**
 * LASSO_IDWSF2_DSTREF_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_DSTREF_HREF "urn:liberty:dst:2006-08:ref"
/**
 * LASSO_IDWSF2_DSTREF_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_DSTREF_PREFIX "dstref"

/**
 * LASSO_IDWSF2_IMS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_IMS_HREF "urn:liberty:ims:2006-08"
/**
 * LASSO_IDWSF2_IMS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_IMS_PREFIX "ims"

/**
 * LASSO_IDWSF2_IS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_IS_HREF "urn:liberty:is:2006-08"
/**
 * LASSO_IDWSF2_IS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_IS_PREFIX "is"

/**
 * LASSO_IDWSF2_PS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_PS_HREF "urn:liberty:ps:2006-08"
/**
 * LASSO_IDWSF2_PS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_PS_PREFIX "ps"

/**
 * LASSO_IDWSF2_SUBS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SUBS_HREF "urn:liberty:ssos:2006-08"
/**
 * LASSO_IDWSF2_SUBS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SUBS_PREFIX "subs"

/**
 * LASSO_IDWSF2_SUBSREF_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SUBSREF_HREF "urn:liberty:ssos:2006-08:ref"
/**
 * LASSO_IDWSF2_SUBSREF_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SUBSREF_PREFIX "subsref"

/**
 * LASSO_IDWSF2_UTIL_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_UTIL_HREF "urn:liberty:util:2006-08"
/**
 * LASSO_IDWSF2_UTIL_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_UTIL_PREFIX "util"

/**
 * LASSO_IDWSF2_SEC_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_IDWSF2_SEC_HREF "urn:liberty:security:2006-08"
/**
 * LASSO_IDWSF2_SEC_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_IDWSF2_SEC_PREFIX "sec"

/*****************************************************************************/
/* WS-*                                                                      */
/*****************************************************************************/

/**
 * LASSO_WSSE_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSSE_HREF "http://schemas.xmlsoap.org/ws/2002/07/secext"
/**
 * LASSO_WSSE_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSSE_PREFIX "wsse"

/**
 * LASSO_WSSE1_HREF:
 *
 * Namespace for WS-Security 1.0
 *
 */
#define LASSO_WSSE1_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
/**
 * LASSO_WSSE1_PREFIX:
 *
 * Preferred prefix for namespace of WS-Security 1.0
 *
 */
#define LASSO_WSSE1_PREFIX "wsse"

/**
 * LASSO_WSSE11_HREF:
 *
 * Namespace for WS-Security 1.1
 */
#define LASSO_WSSE11_HREF \
	"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"

/* LASSO_WSSE11_PREFIX:
 *
 * Preferred prefix for namespace of WS-Security 1.1
 *
 */
#define LASSO_WSSE11_PREFIX "wsse"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_UNSUPPORTED_SECURITY_TOKEN:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_Unsupported_Security_Token \
	"wsse:UnsupportedSecurityToken"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_UNSUPPORTED_ALGORITHM:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_Unsupported_Algorithm \
	"wsse:UnsupportedAlgorithm"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_INVALID_SECURITY:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_Invalid_Security \
	"wsse:InvalidSecurity"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_INVALID_SECURITY_TOKEN:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_Invalid_Security_Token \
	"wsse:InvalidSecurityToken"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_AUTHENTICATION:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_AUTHENTICATION \
	"wsse:FailedAuthentication"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_CHECK:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_FAILED_CHECK \
	"wsse:FailedCheck"

/**
 * LASSO_WSSE_SECEXT_FAULT_CODE_SECURITY_TOKEN_UNAVAILABLE:
 *
 * Fault code for WS-Security tokens handling
 */
#define LASSO_WSSE_SECEXT_FAULT_CODE_SECURITY_TOKEN_UNAVAILABLE \
	"wsse:SecurityTokenUnavailable"

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

/* WS-Addressing */
/**
 * LASSO_WSA_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSA_HREF "http://www.w3.org/2005/08/addressing"
/**
 * LASSO_WSA_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSA_PREFIX "wsa"

/* WS-Utility */
/**
 * LASSO_WSU_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_WSU_HREF \
	"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
/**
 * LASSO_WSU_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_WSU_PREFIX "wsu"

/*****************************************************************************/
/* Others                                                                    */
/*****************************************************************************/

/* xmldsig prefix & href */
/**
 * LASSO_DS_HREF:
 *
 * Namespace for FIXME
 *
 */
#define LASSO_DS_HREF   "http://www.w3.org/2000/09/xmldsig#"
/**
 * LASSO_DS_PREFIX:
 *
 * Preferred prefix for namespace of FIXME
 *
 */
#define LASSO_DS_PREFIX "ds"

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

