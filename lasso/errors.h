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
 */

/**
 * SECTION:errors
 * @short_description: Error codes returned by lasso functions
 * @include: lasso/errors.h
 *
 * Most functions in lasso return signed integer error codes. The convention is to give:
 * <itemizedlist>
 * <listitem><para>a negative error code for programming or runtime recoverable errors,</para></listitem>
 * <listitem><para>a positive error code for Liberty Alliance recoverable errors.</para></listitem>
 * </itemizedlist>
 *
 * <para><emphasis>Beware that this convention is not always well followed.</emphasis></para>
 */

#include "export.h"

LASSO_EXPORT const char* lasso_strerror(int error_code);

/**
 * LASSO_ERROR_UNDEFINED:
 *
 * Undefined error.
 */
#define LASSO_ERROR_UNDEFINED -1
/**
 * LASSO_ERROR_UNIMPLEMENTED:
 *
 * Unimplemented part of Lasso.
 */
#define LASSO_ERROR_UNIMPLEMENTED -2
/**
 * LASSO_ERROR_OUT_OF_MEMORY:
 *
 * Out of memory
 */
#define LASSO_ERROR_OUT_OF_MEMORY -3
/**
 * LASSO_ERROR_CAST_FAILED:
 *
 * Expected GObject class was not found, cast failed
 */
#define LASSO_ERROR_CAST_FAILED -4

/* generic XML */
/**
 * LASSO_XML_ERROR_NODE_NOT_FOUND:
 *
 * Unable to get child of element.
 */
#define LASSO_XML_ERROR_NODE_NOT_FOUND -10
/**
 * LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND:
 *
 * Unable to get content of element.
 */
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND -11
/**
 * LASSO_XML_ERROR_ATTR_NOT_FOUND:
 *
 * Unable to get attribute of element.
 */
#define LASSO_XML_ERROR_ATTR_NOT_FOUND -12
/**
 * LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND:
 *
 * Unable to get attribute value of element.
 */
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND -13
/**
 * LASSO_XML_ERROR_INVALID_FILE:
 *
 * Invalid XML file
 */
#define LASSO_XML_ERROR_INVALID_FILE -14
/**
 * LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED:
 *
 * Construction of an object from an XML document failed.
 */
#define LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED     -15
/**
 * LASSO_XML_ERROR_MISSING_NAMESPACE:
 *
 * A namespace is missing.
 */
#define LASSO_XML_ERROR_MISSING_NAMESPACE              -16
/**
 * LASSO_XML_ERROR_SCHEMA_INVALID_FRAGMENT:
 *
 * An XML tree does not respect at least an XML schema of its namespaces.
 */
#define LASSO_XML_ERROR_SCHEMA_INVALID_FRAGMENT         17
/**
 * LASSO_XML_ERROR_ATTR_VALUE_INVALID:
 *
 * Attribute value is invalid.
 */
#define LASSO_XML_ERROR_ATTR_VALUE_INVALID -18

/* XMLDSig */
/**
 * LASSO_DS_ERROR_SIGNATURE_NOT_FOUND:
 *
 * Signature element not found.
 */
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND 101
/**
 * LASSO_DS_ERROR_INVALID_SIGNATURE:
 *
 * Invalid signature.
 */
#define LASSO_DS_ERROR_INVALID_SIGNATURE 102
#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -103
/**
 * LASSO_DS_ERROR_CONTEXT_CREATION_FAILED:
 *
 * Failed to create signature context.
 */
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED -104
/**
 * LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED:
 *
 * Failed to load public key.
 */
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED -105
/**
 * LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED:
 *
 * Failed to load private key.
 */
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED -106
/**
 * LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED:
 *
 * Failed to load certificate.
 */
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED -107
/**
 * LASSO_DS_ERROR_SIGNATURE_FAILED:
 *
 * Failed to sign the node.
 */
#define LASSO_DS_ERROR_SIGNATURE_FAILED -108
/**
 * LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED:
 *
 * Failed to create keys manager.
 */
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED -109
/**
 * LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED:
 *
 * Failed to initialize keys manager.
 */
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED -110
/**
 * LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED:
 *
 * Failed to verify signature.
 */
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED -111
#define LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED      -112
/**
 * LASSO_DS_ERROR_INVALID_SIGALG:
 *
 * Invalid signature algorithm.
 */
#define LASSO_DS_ERROR_INVALID_SIGALG -113
/**
 * LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED:
 *
 * Computation of an SHA1 digest failed.
 */
#define LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED          -114
/**
 * LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND:
 *
 * Signature template has not been found.
 */
#define LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND -115
/**
 * LASSO_DS_ERROR_TOO_MUCH_REFERENCES:
 *
 * SAML signature must contain only one reference
 */
#define LASSO_DS_ERROR_TOO_MUCH_REFERENCES -116
/**
 * LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML:
 *
 * SAML signature reference must be to a Request, a Reponse or an Assertion ID attribute
 */
#define LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML -117
/**
 * LASSO_DS_ERROR_DECRYPTION_FAILED:
 *
 * Decryption of an encrypted node failed
 */
#define LASSO_DS_ERROR_DECRYPTION_FAILED 118
/**
 * LASSO_DS_ERROR_ENCRYPTION_FAILED:
 *
 * Creation of an encrypted node failed
 */
#define LASSO_DS_ERROR_ENCRYPTION_FAILED -119
/**
 * LASSO_DS_ERROR_DECRYPTION_FAILED_MISSING_PRIVATE_KEY:
 *
 * Could not decrypt because the private key is not present.
 */
#define LASSO_DS_ERROR_DECRYPTION_FAILED_MISSING_PRIVATE_KEY 120


/* Server */
/**
 * LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND:
 *
 * The identifier of a provider is unknown to #LassoServer. To register a provider in a #LassoServer
 * object, you must use the methods lasso_server_add_provider() or
 * lasso_server_add_provider_from_buffer().
 */
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND -201
/**
 * LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED:
 *
 * Failed to add new provider.
 */
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED -202
/**
 * LASSO_SERVER_ERROR_ADD_PROVIDER_PROTOCOL_MISMATCH:
 *
 * Failed to add new provider (protocol mismatch). It means that you tried to add a provider
 * supporting a protocol imcompatible with the protocol declared for your #LassoServer, for example
 * metadata for ID-FF 1.2 with metadata for SAML 2.0.
 */
#define LASSO_SERVER_ERROR_ADD_PROVIDER_PROTOCOL_MISMATCH -203
/**
 * LASSO_SERVER_ERROR_SET_ENCRYPTION_PRIVATE_KEY_FAILED:
 *
 * Failed to load encryption private key.
 */
#define LASSO_SERVER_ERROR_SET_ENCRYPTION_PRIVATE_KEY_FAILED 204
/**
 * LASSO_SERVER_ERROR_INVALID_XML:
 *
 * Parsed XML is invalid.
 */
#define LASSO_SERVER_ERROR_INVALID_XML -205
/**
 * LASSO_SERVER_ERROR_NO_PROVIDER_LOADED
 *
 * When loading a metadata file it indicates that no provider could be loaded.
 * It could be because the file is not well formed, or because there is no provider for the
 * role sought.
 *
 */
#define LASSO_SERVER_ERROR_NO_PROVIDER_LOADED 206

/* Single Logout */
/**
 * LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE:
 *
 * Unsupported protocol profile
 */
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE -301
/**
 * LASSO_LOGOUT_ERROR_REQUEST_DENIED:
 *
 * Request denied by identity provider
 */
#define LASSO_LOGOUT_ERROR_REQUEST_DENIED 302
/**
 * LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND:
 *
 * Federation not found on logout
 */
#define LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND 303
/**
 * LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL:
 *
 * Unknown principal on logout
 */
#define LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL 304
/**
 * LASSO_LOGOUT_ERROR_PARTIAL_LOGOUT:
 *
 * Logout could not be propagated to every service provider in the current session.
 */
#define LASSO_LOGOUT_ERROR_PARTIAL_LOGOUT 305

/* Profile */
/**
 * LASSO_PROFILE_ERROR_INVALID_QUERY:
 *
 * Invalid URL query
 */
#define LASSO_PROFILE_ERROR_INVALID_QUERY -401
/**
 * LASSO_PROFILE_ERROR_INVALID_POST_MSG:
 *
 * Invalid POST message
 */
#define LASSO_PROFILE_ERROR_INVALID_POST_MSG -402
/**
 * LASSO_PROFILE_ERROR_INVALID_SOAP_MSG:
 *
 * Invalid SOAP message
 */
#define LASSO_PROFILE_ERROR_INVALID_SOAP_MSG -403
/**
 * LASSO_PROFILE_ERROR_MISSING_REQUEST:
 *
 * Missing request
 */
#define LASSO_PROFILE_ERROR_MISSING_REQUEST -404
/**
 * LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD:
 *
 * Invalid HTTP method
 */
#define LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD -405
/**
 * LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE:
 *
 * Invalid protocol profile
 */
#define LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE -406
/**
 * LASSO_PROFILE_ERROR_INVALID_MSG:
 *
 * Invalid message
 */
#define LASSO_PROFILE_ERROR_INVALID_MSG -407
/**
 * LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID:
 *
 * ProviderID not found
 */
#define LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID -408
/**
 * LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE:
 *
 * Unsupported protocol profile
 */
#define LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE -409
/**
 * LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL:
 *
 * Unable to find Profile URL in metadata
 */
#define LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL -410
/**
 * LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND:
 *
 * Identity not found
 */
#define LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND -411
/**
 * LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND:
 *
 * Federation not found
 */
#define LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND -412
/**
 * LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND:
 *
 * Name identifier not found
 */
#define LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND -413
/**
 * LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED:
 *
 * Error building request QUERY url
 */
#define LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED -414
/**
 * LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED:
 *
 * Error building request object
 */
#define LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED -415
/**
 * LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED:
 *
 * Error building request message
 */
#define LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED -416
/**
 * LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED:
 *
 * Error building response object
 */
#define LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED -417
/**
 * LASSO_PROFILE_ERROR_SESSION_NOT_FOUND:
 *
 * Session not found
 */
#define LASSO_PROFILE_ERROR_SESSION_NOT_FOUND -418
/**
 * LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP:
 *
 * Failed to create identity from dump
 */
#define LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP -419
/**
 * LASSO_PROFILE_ERROR_BAD_SESSION_DUMP:
 *
 * Failed to create session from dump
 */
#define LASSO_PROFILE_ERROR_BAD_SESSION_DUMP -420
/**
 * LASSO_PROFILE_ERROR_MISSING_RESPONSE:
 *
 * Missing response
 */
#define LASSO_PROFILE_ERROR_MISSING_RESPONSE -421
/**
 * LASSO_PROFILE_ERROR_MISSING_STATUS_CODE:
 *
 * Missing status code
 */
#define LASSO_PROFILE_ERROR_MISSING_STATUS_CODE -422
/**
 * LASSO_PROFILE_ERROR_MISSING_ARTIFACT:
 *
 * Missing SAML artifact
 */
#define LASSO_PROFILE_ERROR_MISSING_ARTIFACT -423
/**
 * LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING:
 *
 * Missing ressource offering
 */
#define LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING 424
/**
 * LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION:
 *
 * Missing service description
 */
#define LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION 425
/**
 * LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE:
 *
 * Missing service type
 */
#define LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE 426
/**
 * LASSO_PROFILE_ERROR_MISSING_ASSERTION:
 *
 * When looking for an assertion we did not found it.
 */
#define LASSO_PROFILE_ERROR_MISSING_ASSERTION -427
/**
 * LASSO_PROFILE_ERROR_MISSING_SUBJECT:
 *
 * Missing subject
 */
#define LASSO_PROFILE_ERROR_MISSING_SUBJECT -428
/**
 * LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER:
 *
 * Missing name identifier
 */
#define LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER -429
/**
 * LASSO_PROFILE_ERROR_INVALID_ARTIFACT:
 *
 * Invalid artifact
 */
#define LASSO_PROFILE_ERROR_INVALID_ARTIFACT -430
/**
 * LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY:
 *
 * Found an encrypted element but encryption private key is not set
 */
#define LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY -431
/**
 * LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS:
 *
 * Status code is not success
 */
#define LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS -432
/**
 * LASSO_PROFILE_ERROR_MISSING_ISSUER:
 *
 * Missing issuer
 */
#define LASSO_PROFILE_ERROR_MISSING_ISSUER -433
/**
 * LASSO_PROFILE_ERROR_MISSING_SERVICE_INSTANCE:
 *
 * Missing service instance
 */
#define LASSO_PROFILE_ERROR_MISSING_SERVICE_INSTANCE -434
/**
 * LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE:
 *
 * Missing endpoint reference
 */
#define LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE -435
/**
 * LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE_ADDRESS:
 *
 * Missing endpoint reference address
 */
#define LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE_ADDRESS -436
/**
 * LASSO_PROFILE_ERROR_INVALID_ISSUER:
 *
 * Assertion issuer is not the same as the requested issuer
 */
#define LASSO_PROFILE_ERROR_INVALID_ISSUER -437
/**
 * LASSO_PROFILE_ERROR_MISSING_SERVER:
 *
 * No server object set in the profile
 */
#define LASSO_PROFILE_ERROR_MISSING_SERVER -438
/**
 * LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER:
 * @Deprecated: Since 2.2.3
 *
 * The issuer of the message is unknown to us
 */
#define LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER 439
/**
 * LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE:
 *
 * The profile cannot verify a signature on the message
 */
#define LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE 440
/**
 * LASSO_PROFILE_ERROR_CANNOT_FIND_A_PROVIDER:
 *
 * Profile was called without a specific provider and we cannot find one.
 */
#define LASSO_PROFILE_ERROR_CANNOT_FIND_A_PROVIDER -441
/**
 * LASSO_PROFILE_ERROR_RESPONSE_DOES_NOT_MATCH_REQUEST:
 *
 * Received response does not refer to the request sent
 */
#define LASSO_PROFILE_ERROR_RESPONSE_DOES_NOT_MATCH_REQUEST -442
/**
 * LASSO_PROFILE_ERROR_INVALID_REQUEST:
 *
 * Received request is not of the expected type.
 */
#define LASSO_PROFILE_ERROR_INVALID_REQUEST 443

/*
 * LASSO_PROFILE_ERROR_INVALID_REQUEST:
 *
 * Received request is not of the expected type.
 */
#define LASSO_PROFILE_ERROR_INVALID_RESPONSE 444
/**
 * LASSO_PROFILE_ERROR_UNSUPPPORTED_BINDING
 *
 * The responder reported that he does not support this binding
 */
#define LASSO_PROFILE_ERROR_UNSUPPORTED_BINDING 445
/**
 * LASSO_PROFILE_ERROR_INVALID_ASSERTION_CONDITIONS:
 *
 * An assertion conditions could not be validated.
 */
#define LASSO_PROFILE_ERROR_INVALID_ASSERTION_CONDITIONS 446
/**
 * LASSO_PROFILE_ERROR_INVALID_ASSERTION:
 *
 * The assertion is malformed, Issuer differs from NameQualifier of the subject, signature cannot be
 * verified.
 */
#define LASSO_PROFILE_ERROR_INVALID_ASSERTION 447
/**
 * LASSO_PROFILE_ERROR_UNKNOWN_ISSUER:
 *
 * The issuer of an assertion is unkown to us.
 */
#define LASSO_PROFILE_ERROR_UNKNOWN_ISSUER 448
/**
 * LASSO_PROFILE_ERROR_ISSUER_IS_NOT_AN_IDP
 *
 * The issuer of an assertion is not considered as an IdP
 */
#define LASSO_PROFILE_ERROR_ISSUER_IS_NOT_AN_IDP 449
/**
 * LASSO_PROFILE_ERROR_REQUEST_DENIED:
 *
 * Generic error when an IdP or an SP return the RequestDenied status code in its response.
 *
 */
#define LASSO_PROFILE_ERROR_REQUEST_DENIED 450
/**
 * LASSO_PROFILE_ERROR_ENDPOINT_INDEX_NOT_FOUND
 *
 * A received artifact contains an andpoint index which does not exist in the metadata of the
 * corresponding provider.
 */
#define LASSO_PROFILE_ERROR_ENDPOINT_INDEX_NOT_FOUND 451
/**
 * LASSO_PROFILE_ERROR_INVALID_IDP_LIST
 *
 * The IDP list is invalid
 */
#define LASSO_PROFILE_ERROR_INVALID_IDP_LIST 452

/* functions/methods parameters checking */
/**
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ:
 *
 * An object type provided as parameter is invalid or object is NULL.
 */
#define LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ -501
/**
 * LASSO_PARAM_ERROR_INVALID_VALUE:
 *
 * A parameter value is invalid.
 */
#define LASSO_PARAM_ERROR_INVALID_VALUE -502
/**
 * LASSO_PARAM_ERROR_CHECK_FAILED:
 *
 * The error return location should be either NULL or contains a NULL error.
 */
#define LASSO_PARAM_ERROR_CHECK_FAILED -503
/**
 * LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT:
 *
 * The call failed because an argument is a partially-initialized object.
 */
#define LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT      -504

/* Single Sign-On */
/**
 * LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND:
 *
 * Federation not found on login
 */
#define LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND 601
/**
 * LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED:
 *
 * Consent of the principal was not obtained.
 */
#define LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED         602
/**
 * LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY:
 *
 * Invalid NameIDPolicy in lib:AuthnRequest
 */
#define LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY -603
/**
 * LASSO_LOGIN_ERROR_REQUEST_DENIED:
 *
 * Request denied.
 */
#define LASSO_LOGIN_ERROR_REQUEST_DENIED 604
/**
 * LASSO_LOGIN_ERROR_INVALID_SIGNATURE:
 *
 * The signature of a message or of an assertion is invalid. That is badly computed or with an
 * unknown key.
 */
#define LASSO_LOGIN_ERROR_INVALID_SIGNATURE            605
/**
 * LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST:
 *
 * An unsigned authn request was received but the metadata specify that they must be signed.
 */
#define LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST       606
/**
 * LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS:
 *
 * Status code is not success
 */
#define LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS 607
/**
 * LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL:
 *
 * Unknown principal
 */
#define LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL 608
/**
 * LASSO_LOGIN_ERROR_NO_DEFAULT_ENDPOINT:
 *
 * No default endpoint
 */
#define LASSO_LOGIN_ERROR_NO_DEFAULT_ENDPOINT 609
/**
 * LASSO_LOGIN_ERROR_ASSERTION_REPLAY:
 *
 * Assertion replay
 */
#define LASSO_LOGIN_ERROR_ASSERTION_REPLAY 610
/**
 * LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID:
 *
 * If inResponseTo attribute is present, a matching request must be present too in the LassoLogin object
 */
#define LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID 611

/**
 * LASSO_LOGIN_ERROR_INVALID_ASSERTION_SIGNATURE:
 *
 * Signature on an assertion could not be verified.
 */
#define LASSO_LOGIN_ERROR_INVALID_ASSERTION_SIGNATURE 612

/* Federation Termination Notification */
/**
 * LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER:
 *
 * Name identifier not found in request
 */
#define LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER -700

/* Soap */
/**
 * LASSO_SOAP_ERROR_REDIRECT_REQUEST_FAULT:
 *
 * A SOAP Fault containing a Redirect Request was received
 */
#define LASSO_SOAP_ERROR_REDIRECT_REQUEST_FAULT 800
#define LASSO_SOAP_FAULT_REDIRECT_REQUEST LASSO_SOAP_ERROR_REDIRECT_REQUEST_FAULT

/**
 * LASSO_SOAP_ERROR_MISSING_ENVELOPE:
 *
 * Missing SOAP envelope
 */
#define LASSO_SOAP_ERROR_MISSING_ENVELOPE -801
/**
 * LASSO_SOAP_ERROR_MISSING_HEADER:
 *
 * Missing SOAP header
 */
#define LASSO_SOAP_ERROR_MISSING_HEADER -802
/**
 * LASSO_SOAP_ERROR_MISSING_BODY:
 *
 * Missing SOAP body
 */
#define LASSO_SOAP_ERROR_MISSING_BODY -803
/**
 * LASSO_SOAP_ERROR_MISSING_SOAP_FAULT_DETAIL:
 *
 * Missing SOAP fault detail
 */
#define LASSO_SOAP_ERROR_MISSING_SOAP_FAULT_DETAIL -804

/* Name Identifier Mapping */
/**
 * LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_NAMESPACE:
 *
 * Target name space not found
 */
#define LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_NAMESPACE -900
#define LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE -901
#define LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_IDENTIFIER -902

/* Data Service */
#define LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST    -1000
#define LASSO_DATA_SERVICE_ERROR_CANNOT_ADD_ITEM           -1001

/* WSF Profile */
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION:
 *
 * Correlation SOAP Header is missing
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION -1100
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_SECURITY:
 *
 * Security SOAP Header is missing
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_SECURITY -1101
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_ASSERTION_ID:
 *
 * AssertionID attribute is missing
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_ASSERTION_ID -1102
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_ENDPOINT:
 *
 * Cannot find an WSP endpoint for the ID-WSF service
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_ENDPOINT -1103
/**
 * LASSO_WSF_PROFILE_ERROR_SOAP_FAULT:
 *
 * SOAP ID-WSF binding returned a SOAP fault
 */
#define LASSO_WSF_PROFILE_ERROR_SOAP_FAULT 1104
/**
 * LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM:
 *
 * The specified security mechanism is not supported by lasso ID-WSF library
 */
#define LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM 1105
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_DESCRIPTION:
 *
 * No ID-WSF web Service description could be found for the current security mechanism
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_DESCRIPTION -1106
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_RESOURCE_ID:
 *
 * The necessary ResourceID or EncryptedResourceID for calling an ID-WSF service is missing.
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_RESOURCE_ID -1107
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_CREDENTIAL_REF:
 *
 * WS-Security SAML Token secmech needs a CredentialRef
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_CREDENTIAL_REF -1108
/**
 * LASSO_WSF_PROFILE_ERROR_INVALID_OR_MISSING_REFERENCE_TO_MESSAGE_ID:
 *
 * refToMessageID attribute of the Corrrelation header does not match the SOAP request
 */
#define LASSO_WSF_PROFILE_ERROR_INVALID_OR_MISSING_REFERENCE_TO_MESSAGE_ID -1109
/**
 * LASSO_WSF_PROFILE_ERROR_SECURITY_MECHANISM_CHECK_FAILED:
 *
 * Check for a security mechanism upon a received request failed.
 */
#define LASSO_WSF_PROFILE_ERROR_SECURITY_MECHANISM_CHECK_FAILED 1110

/**
 * LASSO_WSF_PROFILE_ERROR_UNKNOWN_STATUS_CODE:
 *
 * A response contained an unknown status code.
 */
#define LASSO_WSF_PROFILE_ERROR_UNKNOWN_STATUS_CODE 1112
/**
 * LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED:
 *
 * A interaction is required but the sender did not allow use to make interact redirect requests.
 */
#define LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED 1113
/**
 * LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED_FOR_DATA:
 *
 * A interaction is required to get fresh datas but the sender did not allow use to make interact
 * redirect requests.
 */
#define LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED_FOR_DATA 1114
/**
 * LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST:
 *
 * The last parsed response contained a SOAP fault with a RedirectRequest element.
 */
#define LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST 1115
/**
 * LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST_UNSUPPORTED_BY_REQUESTER:
 *
 * The requester does not support SOAP Fault containing RedirectRequest elements. So it is not
 * possible to use lasso_idwsf2_profile_redirect_user_for_interaction().
 */
#define LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST_UNSUPPORTED_BY_REQUESTER 1116
/**
 * LASSO_WSF_PROFILE_ERROR_MISSING_SENDER_ID:
 *
 * The received ID-WSF request miss a Sender id.
 */
#define LASSO_WSF_PROFILE_ERROR_MISSING_SENDER_ID 1117


/* ID-WSF 2 Discovery */
/**
 * LASSO_DISCOVERY_ERROR_SVC_METADATA_REGISTER_FAILED:
 *
 * Service metadata registration failed
 */
#define LASSO_DISCOVERY_ERROR_SVC_METADATA_REGISTER_FAILED -1200
/**
 * LASSO_DISCOVERY_ERROR_SVC_METADATA_ASSOCIATION_ADD_FAILED:
 *
 * Service metadata association failed
 */
#define LASSO_DISCOVERY_ERROR_SVC_METADATA_ASSOCIATION_ADD_FAILED -1201
/**
 * LASSO_DISCOVERY_ERROR_MISSING_REQUESTED_SERVICE:
 *
 * Missing requested service
 */
#define LASSO_DISCOVERY_ERROR_MISSING_REQUESTED_SERVICE -1202
/**
 * LASSO_DISCOVERY_ERROR_FAILED_TO_BUILD_ENDPOINT_REFERENCE:
 *
 * Failed to build Endpoint Reference
 */
#define LASSO_DISCOVERY_ERROR_FAILED_TO_BUILD_ENDPOINT_REFERENCE -1203

/* ID-WSF 2 Data Service */
/**
 * LASSO_DST_ERROR_MISSING_SERVICE_DATA:
 *
 * Missing service data
 */
#define LASSO_DST_ERROR_MISSING_SERVICE_DATA -1300
/**
 * LASSO_DST_ERROR_QUERY_FAILED:
 *
 * Query failed
 */
#define LASSO_DST_ERROR_QUERY_FAILED -1301
/**
 * LASSO_DST_ERROR_QUERY_PARTIALLY_FAILED:
 *
 * Query partially failed : some items were correctly processed
 */
#define LASSO_DST_ERROR_QUERY_PARTIALLY_FAILED -1302
/**
 * LASSO_DST_ERROR_MODIFY_FAILED:
 *
 * Modify failed
 */
#define LASSO_DST_ERROR_MODIFY_FAILED -1303
/**
 * LASSO_DST_ERROR_MODIFY_PARTIALLY_FAILED:
 *
 * Modify partially failed : some items were correctly processed
 */
#define LASSO_DST_ERROR_MODIFY_PARTIALLY_FAILED -1304
/**
 * LASSO_DST_ERROR_NEW_DATA_MISSING:
 *
 * Missing new data
 */
#define LASSO_DST_ERROR_NEW_DATA_MISSING -1305
/**
 * LASSO_DST_ERROR_QUERY_NOT_FOUND:
 *
 * Looked query is not found
 */
#define LASSO_DST_ERROR_QUERY_NOT_FOUND -1306
/**
 * LASSO_DST_ERROR_NO_DATA:
 *
 * No data or no data for the designated query item in the query response
 */
#define LASSO_DST_ERROR_NO_DATA -1307
/**
 * LASSO_DST_ERROR_MALFORMED_QUERY:
 *
 * QueryObject is malformed
 */
#define LASSO_DST_ERROR_MALFORMED_QUERY -1308
/**
 * LASSO_DST_ERROR_EMPTY_REQUEST
 *
 * Request is empty.
 */
#define LASSO_DST_ERROR_EMPTY_REQUEST -1309

/* Lasso registry */
/**
 * LASSO_REGISTRY_ERROR_KEY_EXISTS:
 *
 * Key alreadys exists in the registry
 */
#define LASSO_REGISTRY_ERROR_KEY_EXISTS -1400

/* Lasso provider */
/**
 * LASSO_PROVIDER_ERROR_MISSING_PUBLIC_KEY:
 *
 * The provider has no known public key
 */
#define LASSO_PROVIDER_ERROR_MISSING_PUBLIC_KEY -1500

/* WS-Security */
/**
 * LASSO_WSSEC_ERROR_MISSING_SECURITY_TOKEN:
 *
 * The request miss a WS-Security token.
 */
#define LASSO_WSSEC_ERROR_MISSING_SECURITY_TOKEN 1600

/**
 * LASSO_WSSEC_ERROR_BAD_PASSWORD:
 *
 * The known password does not match the UsernameToken
 */
#define LASSO_WSSEC_ERROR_BAD_PASSWORD 1601

/* ID-WSF 2.0 Discovery Service */
/**
 * LASSO_IDWSF2_DISCOVERY_ERROR_FAILED:
 *
 * Last discovery request failed.
 */
#define LASSO_IDWSF2_DISCOVERY_ERROR_FAILED 1700
/**
 * LASSO_IDWSF2_DISCOVERY_ERROR_FORBIDDEN:
 *
 * Last discovery request is forbidden by policy.
 */
#define LASSO_IDWSF2_DISCOVERY_ERROR_FORBIDDEN 1701
/**
 * LASSO_IDWSF2_DISCOVERY_ERROR_DUPLICATE:
 *
 * Last discovery request was denied because it would result in duplicate data in the service
 */
#define LASSO_IDWSF2_DISCOVERY_ERROR_DUPLICATE 1702
/**
 * LASSO_IDWSF2_DISCOVERY_ERROR_LOGICAL_DUPLICATE:
 *
 * Last discovery request was denied because it would result in logically duplicate data in the service
 */
#define LASSO_IDWSF2_DISCOVERY_ERROR_LOGICAL_DUPLICATE 1703
/**
 * LASSO_IDWSF2_DISCOVERY_ERROR_NO_RESULTS:
 *
 * The discovery query had no matching results.
 */
#define LASSO_IDWSF2_DISCOVERY_ERROR_NO_RESULTS 1704
/**
 * LASSO_IDWSF2_DISCOVERY_ERROR_NOT_FOUND:
 *
 * The specified item(s) were not found.
 */
#define LASSO_IDWSF2_DISCOVERY_ERROR_NOT_FOUND 1705

/* ID-WSF 2.0 Data Service Template */

/**
 * LASSO_IDWSF2_DST_ERROR_DUPLICATE_ITEM:
 *
 * A call to add a new item would result in duplicate items.
 */
#define LASSO_IDWSF2_DST_ERROR_DUPLICATE_ITEM -1801

/**
 * LASSO_IDWSF2_DST_ERROR_PARTIAL_FAILURE:
 *
 * Server responded with a partial failure status code.
 */
#define LASSO_IDWSF2_DST_ERROR_PARTIAL_FAILURE 1802

/**
 * LASSO_IDWSF2_DST_ERROR_UNKNOWN_STATUS_CODE:
 *
 * Server response with an unknown status code.
 */
#define LASSO_IDWSF2_DST_ERROR_UNKNOWN_STATUS_CODE 1803
/**
 * LASSO_IDWSF2_DST_ERROR_ITEM_NOT_FOUND:
 *
 * The item_id was not found in the current query request.
 */
#define LASSO_IDWSF2_DST_ERROR_ITEM_NOT_FOUND 1804

/**
 * LASSO_ASSERTION_QUERY_ERROR_ATTRIBUTE_REQUEST_ALREADY_EXIST:
 *
 * Tried to add the same attribute request a second time.
 */
#define LASSO_ASSERTION_QUERY_ERROR_ATTRIBUTE_REQUEST_ALREADY_EXIST 1901

/**
 * LASSO_ASSERTION_QUERY_ERROR_NOT_AN_ATTRIBUTE_QUERY
 *
 * The current assertion query does not contain an attribute query.
 */
#define LASSO_ASSERTION_QUERY_ERROR_NOT_AN_ATTRIBUTE_QUERY 1902

/**
 * LASSO_XMLENC_ERROR_INVALID_ENCRYPTED_DATA
 *
 * The EncryptedData node is invalid, look at the logs.
 */
#define LASSO_XMLENC_ERROR_INVALID_ENCRYPTED_DATA -2001

/**
 * LASSO_PAOS_ERROR_MISSING_REQUEST
 *
 * Missing PAOS Request
 */
#define LASSO_PAOS_ERROR_MISSING_REQUEST -2101
/**
 * LASSO_PAOS_ERROR_MISSING_RESPONSE
 *
 * Missing PAOS Response
 */
#define LASSO_PAOS_ERROR_MISSING_RESPONSE -2102
/**
 * LASSO_PAOS_ERROR_MISSING_RESPONSE_CONSUMER_URL
 *
 * Missing paos:Request responseConsumerURL
 */
#define LASSO_PAOS_ERROR_MISSING_RESPONSE_CONSUMER_URL -2103

/**
 * LASSO_ECP_ERROR_MISSING_REQUEST
 *
 * Missing ECP Request
 */
#define LASSO_ECP_ERROR_MISSING_REQUEST -2201
/**
 * LASSO_ECP_ERROR_MISSING_RESPONSE
 *
 * Missing ECP Response
 */
#define LASSO_ECP_ERROR_MISSING_RESPONSE -2202
/**
 * LASSO_ECP_ERROR_MISSING_RELAYSTATE
 *
 * Missing ECP RelayState
 */
#define LASSO_ECP_ERROR_MISSING_RELAYSTATE -2203
/**
 * LASSO_ECP_ERROR_MISSING_AUTHN_REQUEST
 *
 * Missing samlp:AuthnRequest in ECP request
 */
#define LASSO_ECP_ERROR_MISSING_AUTHN_REQUEST -2204
/**
 * LASSO_ECP_ERROR_MISSING_SAML_RESPONSE
 *
 * Missing samlp:Response in IdP ECP response
 */
#define LASSO_ECP_ERROR_MISSING_SAML_RESPONSE -2205
/**
 * LASSO_ECP_ERROR_ASSERTION_CONSUMER_URL_MISMATCH
 *
 * The ecp:Request responseConsumerURL and ecp:Response AssertionConsumerURL do not match
 */
#define LASSO_ECP_ERROR_ASSERTION_CONSUMER_URL_MISMATCH -2206
