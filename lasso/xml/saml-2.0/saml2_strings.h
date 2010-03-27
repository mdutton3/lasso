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
 *
 */

/**
 * SECTION:saml2_strings
 * @short_description: String constants from SAML 2.0 specifications
 * @long_desscription: A lots of elements contains URL or enum based content, 
 * @include: lasso/xml/saml-2.0/saml2_strings.h
 * @stability: Stable
 * @see_also: #LassoSamlp2AuthnRequest, #LassoSaml2Assertion, #LassoLogin
 */

#ifndef __LASSO_SAML2_STRINGS_H__
#define __LASSO_SAML2_STRINGS_H__

/**
 * LASSO_SAML2_METADATA_HREF:
 *
 * Namespace for SAML 2.0 metadata
 *
 */
#define LASSO_SAML2_METADATA_HREF "urn:oasis:names:tc:SAML:2.0:metadata"

/**
 * LASSO_SAML2_METADATA_PREFIX:
 *
 * Preferred prefix for namespace of SAML 2.0 metadata
 */
#define LASSO_SAML2_METADATA_PREFIX "md"

/**
 * LASSO_SAML2_PROTOCOL_HREF:
 *
 * Namespace for SAML 2.0 protocol.
 *
 */
#define LASSO_SAML2_PROTOCOL_HREF "urn:oasis:names:tc:SAML:2.0:protocol"
/**
 * LASSO_SAML2_PROTOCOL_PREFIX:
 *
 * Preferred prefix for namespace of SAML 2.0 protocol
 *
 */
#define LASSO_SAML2_PROTOCOL_PREFIX "samlp"

/**
 * LASSO_SAML2_ASSERTION_HREF:
 *
 * Namespace for SAML 2.0 assertion
 *
 */
#define LASSO_SAML2_ASSERTION_HREF "urn:oasis:names:tc:SAML:2.0:assertion"
/**
 * LASSO_SAML2_ASSERTION_PREFIX:
 *
 * Preferred prefix for namespace of SAML 2.0 assertion
 *
 */
#define LASSO_SAML2_ASSERTION_PREFIX "saml"

/* Bindings URIs */

/**
 * LASSO_SAML2_METADATA_BINDING_SOAP:
 *
 * URI for the SOAP binding.
 */
#define LASSO_SAML2_METADATA_BINDING_SOAP "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

/**
 * LASSO_SAML2_METADATA_BINDING_REDIRECT:
 *
 * URI for the HTTP-Redirect binding.
 */
#define LASSO_SAML2_METADATA_BINDING_REDIRECT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
/**
 * LASSO_SAML2_METADATA_BINDING_POST:
 *
 * URI for the HTTP-Post binding.
 */
#define LASSO_SAML2_METADATA_BINDING_POST "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

/**
 * LASSO_SAML2_METADATA_BINDING_ARTIFACT:
 *
 * URI for the HTTP-Artifact binding.
 */
#define LASSO_SAML2_METADATA_BINDING_ARTIFACT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

/**
 * LASSO_SAML2_METADATA_BINDING_PAOS:
 *
 * URI for the PAOS (or reverse SOAP) binding.
 */
#define LASSO_SAML2_METADATA_BINDING_PAOS "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

/**
 * LASSO_SAML2_METADATA_BINDING_URI:
 *
 * URI for the URI special binding.
 */
#define LASSO_SAML2_METADATA_BINDING_URI "urn:oasis:names:tc:SAML:2.0:bindings:URI"

/**
 * LASSO_SAML2_DEFLATE_ENCODING:
 *
 * URI for URL-Encoding of kind DEFLATE (compress message content before encoding in the URI).
 */
#define LASSO_SAML2_DEFLATE_ENCODING "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"


/* Name Identifier Format */

/* note that SAML 2.0 can also use SAML 1.1 name identifier formats */

/**
 * LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED:
 * 
 * <para>Name identifier format for local names, or free format name.</para>
 *
 * From saml-core-2.0-os.pdf:
 * <blockquote>The interpretation of the content of the element is left to individual implementations.</blockquote>
 */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_UNSPECIFIED \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
/**
 * LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL:
 * 
 * <para>Name identifier format for email addresses.</para>
 *
 * From saml-core-2.0-os.pdf:
 * <blockquote>Indicates that the content of the element is in the form of an email address,
 * specifically "addr-spec" as defined in IETF RFC 2822 [RFC 2822] Section 3.4.1. An addr-spec has
 * the form local-part@domain.  Note that an addr-spec has no phrase (such as a common name) before
 * it, has no comment (text surrounded in parentheses) after it, and is not surrounded by "<" and
 * ">". </blockquote>
 */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_X509 \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_WINDOWS \
		"urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
/**
 * LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY:
 * 
 * <para>Name identifier format for SAML 2.0 entities, i.e. identity and service providers.</para>
 *
 * From saml-core-2.0-os.pdf: 
 * <blockquote><para>Indicates that the content of the element is the
 * identifier of an entity that provides SAML-based services
 (such as a SAML authority, requester, or responder) or is a participant in SAML profiles (such as a
 * service provider supporting the browser SSO profile). Such an identifier can be used in the
 * &lt;Issuer&gt; element to identify the issuer of a SAML request, response, or assertion, or within the
 * &lt;NameID&gt; element to make assertions about system entities that can issue SAML requests,
 * responses, and assertions. It can also be used in other elements and attributes whose purpose is
 * to identify a system entity in various protocol exchanges.</para> <para>The syntax of such an
 * identifier is a URI of not more than 1024 characters in length. It is RECOMMENDED that a system
 * entity use a URL containing its own domain name to identify itself.</para> <para>The
 * NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted.</para></blockquote>
 */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
/**
 * LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT:
 *
 * <para>Name identifier format for SAML 2.0 federation.</para>
 *
 */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
/**
 * LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT:
 *
 * <para>Name identifier format for temporary SAML 2.0 federation.</para>
 */
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

/* Attribute Names */

/**
 * LASSO_SAML2_ATTRIBUTE_NAME_EPR:
 *
 * Attribute name for tranmitting Discovery bootstrap EPR when using ID-WSF 2.0 framework. It must
 * be used conjointly with #LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI as format for the attribute
 * element.
 */
#define LASSO_SAML2_ATTRIBUTE_NAME_EPR "urn:liberty:disco:2006-08:DiscoveryEPR"

/* Attribute Name Format */

/**
 * LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_UNSPECIFIED:
 *
 * Attribute format whose interpretation is left to individual implementations.
 */
#define LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_UNSPECIFIED "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

/**
 * LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI:
 *
 * From saml-core-2.0-os.pdf:
 * <blockquote>The attribute name follows the convention for URI references [RFC 2396], for example
 * as used in XACML attribute identifiers. The interpretation of the URI content or naming
 * scheme is
 application- specific. See [SAMLProf] for attribute profiles that make use of this identifier.</blockquote>
 */
#define LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

/**
 * LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_BASIC:
 *
 * Attribute format whose names are in the xs:Name domain.
 */
#define LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_BASIC "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

/* Actions */

/* Actions are used by the Authorization profile */

/**
 * LASSO_SAML2_ACTION_NAMESPACE_RWEDC:
 *
 * Namespace for actions among: Read, Write, Execute, Delete and Control.
 */
#define LASSO_SAML2_ACTION_NAMESPACE_RWEDC "urn:oasis:names:tc:SAML:1.0:action:rwedc"

/**
 * LASSO_SAML2_ACTION_NAMESPACE_RWEDC_NEGATION:
 *
 * Namespace for actions among: Read, Write, Execute, Delete and Control and their negations, ~Read,
 * ~Write, ~Execute, ~Delete, ~Control.
 */
#define LASSO_SAML2_ACTION_NAMESPACE_RWEDC_NEGATION "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation"

/**
 * LASSO_SAML2_ACTION_NAMESPACE_GHPP:
 *
 * Namespace for actions among: GET, HEAD, PUT, POST.
 */
#define LASSO_SAML2_ACTION_NAMESPACE_GHPP "urn:oasis:names:tc:SAML:1.0:action:ghpp"

/**
 * LASSO_SAML2_ACTION_NAMESPACE_UNIX:
 *
 * Namespace for actions represented by a four digit numeric code in octal value, as Unix file
 * permissions codes.
 */
#define LASSO_SAML2_ACTION_NAMESPACE_UNIX "urn:oasis:names:tc:SAML:1.0:action:unix"

/* Individual actions */
#define LASSO_SAML2_ACTION_RWEDC_READ "Read"
#define LASSO_SAML2_ACTION_RWEDC_WRITE "Write"
#define LASSO_SAML2_ACTION_RWEDC_EXECUTE "Execute"
#define LASSO_SAML2_ACTION_RWEDC_DELETE "Delete"
#define LASSO_SAML2_ACTION_RWEDC_CONTROL "Control"
#define LASSO_SAML2_ACTION_RWEDC_NEGATION "~"

#define LASSO_SAML2_ACTION_GHPP_GET "GET"
#define LASSO_SAML2_ACTION_GHPP_HEAD "HEAD"
#define LASSO_SAML2_ACTION_GHPP_PUT "PUT"
#define LASSO_SAML2_ACTION_GHPP_POST "POST"

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
#define LASSO_SAML2_CONFIRMATION_METHOD_HOLDER_OF_KEY "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"

/* POST and GET request fields */
#define LASSO_SAML2_FIELD_ENCODING "SAMLEncoding"
#define LASSO_SAML2_FIELD_RESPONSE "SAMLResponse"
#define LASSO_SAML2_FIELD_REQUEST "SAMLRequest"
#define LASSO_SAML2_FIELD_ARTIFACT "SAMLart"
#define LASSO_SAML2_FIELD_RELAYSTATE "RelayState"
#define LASSO_SAML2_FIELD_SIGNATURE "Signature"
#define LASSO_SAML2_FIELD_SIGALG "SigAlg"

/* SAML 2.0 Attribute Profiles */

#define LASSO_SAML2_ATTRIBUTE_PROFILE_BASIC "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic"
#define LASSO_SAML2_ATTRIBUTE_PROFILE_X500 "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"
#define LASSO_SAML2_ATTRIBUTE_PROFILE_UUID "urn:oasis:names:tc:SAML:2.0:profiles:attribute:UUID"
#define LASSO_SAML2_ATTRIBUTE_PROFILE_DCE "urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE"

#endif /* __LASSO_SAML2_STRINGS_H__ */
