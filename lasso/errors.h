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

/* Negative errors : programming or runtime recoverable errors */
/* Positive errors : Liberty Alliance recoverable errors */

/* undefined */
#define LASSO_ERROR_UNDEFINED                           -1 /* Undefined error case */
#define LASSO_ERROR_UNIMPLEMENTED                       -2 /* Unimplemented part of Lasso */

/* generic XML */
#define LASSO_XML_ERROR_NODE_NOT_FOUND                 -10 /* Unable to get child of element. */
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND         -11 /* Unable to get content of element. */
#define LASSO_XML_ERROR_ATTR_NOT_FOUND                 -12 /* Unable to get attribute of element. */
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND           -13 /* Unable to get attribute value of element. */
#define LASSO_XML_ERROR_INVALID_FILE                   -14 /* Invalid XML file */
#define LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED     -15
#define LASSO_XML_ERROR_MISSING_NAMESPACE              -16

/* XMLDSig */
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND             101 /* Signature element not found. */
#define LASSO_DS_ERROR_INVALID_SIGNATURE               102 /* Invalid signature. */
#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -103
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED        -104 /* Failed to create signature context. */
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED         -105 /* Failed to load public key. */
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED        -106 /* Failed to load private key. */
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED        -107 /* Failed to load certificate. */
#define LASSO_DS_ERROR_SIGNATURE_FAILED               -108 /* Failed to sign the node. */
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED      -109 /* Failed to create keys manager. */
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED          -110 /* Failed to initialize keys manager. */
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED  -111 /* Failed to verify signature. */
#define LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED      -112
#define LASSO_DS_ERROR_INVALID_SIGALG                 -113 /* Invalid signature algorithm. */
#define LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED          -114
#define LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND   -115 /* Signature template has not been found. */

/* Server */
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND         -201 /* ProviderID unknown to LassoServer. */
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED        -202 /* Failed to add new provider. */
#define LASSO_SERVER_ERROR_ADD_PROVIDER_PROTOCOL_MISMATCH -203 /* Failed to add new provider (protocol mismatch). */
#define LASSO_SERVER_ERROR_SET_ENCRYPTION_PRIVATE_KEY_FAILED 204 /* Failed to load encryption private key. */
#define LASSO_SERVER_ERROR_INVALID_XML                -205

/* Single Logout */
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE        -301 /* Unsupported protocol profile */
#define LASSO_LOGOUT_ERROR_REQUEST_DENIED              302 /* Request denied by identity provider */
#define LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND        303 /* Federation not found on logout */
#define LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL           304 /* Unknown principal on logout */

/* Profile */
#define LASSO_PROFILE_ERROR_INVALID_QUERY             -401 /* Invalid URL query */
#define LASSO_PROFILE_ERROR_INVALID_POST_MSG          -402 /* Invalid POST message */
#define LASSO_PROFILE_ERROR_INVALID_SOAP_MSG          -403 /* Invalid SOAP message */
#define LASSO_PROFILE_ERROR_MISSING_REQUEST           -404 /* Missing request */
#define LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD       -405 /* Invalid HTTP method */
#define LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE   -406 /* Invalid protocol profile */
#define LASSO_PROFILE_ERROR_INVALID_MSG               -407 /* Invalid message */
#define LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID -408 /* ProviderID not found */
#define LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE       -409 /* Unsupported protocol profile */
#define LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL       -410 /* Unable to find Profile URL in metadata */
#define LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND        -411 /* Identity not found */
#define LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND      -412 /* Federation not found */
#define LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND -413 /* Name identifier not found */
#define LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED     -414 /* Error building request QUERY url */
#define LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED   -415 /* Error building request object */
#define LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED   -416 /* Error building request message */
#define LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED  -417 /* Error building response object */
#define LASSO_PROFILE_ERROR_SESSION_NOT_FOUND         -418 /* Session not found */
#define LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP         -419 /* Failed to create identity from dump */
#define LASSO_PROFILE_ERROR_BAD_SESSION_DUMP          -420 /* Failed to create session from dump */
#define LASSO_PROFILE_ERROR_MISSING_RESPONSE          -421 /* Missing response */
#define LASSO_PROFILE_ERROR_MISSING_STATUS_CODE       -422 /* Missing status code */
#define LASSO_PROFILE_ERROR_MISSING_ARTIFACT          -423 /* Missing SAML artifact */
#define LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING      424 /* Missing ressource offering */
#define LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION    425 /* Missing service description */
#define LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE           426 /* Missing service type */
#define LASSO_PROFILE_ERROR_MISSING_ASSERTION         -427 /* Missing assertion */
#define LASSO_PROFILE_ERROR_MISSING_SUBJECT           -428 /* Missing subject */
#define LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER   -429 /* Missing name identifier */
#define LASSO_PROFILE_ERROR_INVALID_ARTIFACT          -430 /* Invalid artifact */
#define LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY -431 /* Found an encrypted element but encryption private key is not set */
#define LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS        -432 /* Status code is not success */
#define LASSO_PROFILE_ERROR_MISSING_ISSUER            -433 /* Missing issuer */
#define LASSO_PROFILE_ERROR_MISSING_SERVICE_INSTANCE  -434 /* Missing service instance */
#define LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE -435 /* Missing endpoint reference */
#define LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE_ADDRESS -436 /* Missing endpoint reference address */

/* functions/methods parameters checking */
#define LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ        -501 /* An object type provided as parameter  */
#define LASSO_PARAM_ERROR_INVALID_VALUE               -502 /* A parameter value is invalid. */
#define LASSO_PARAM_ERROR_CHECK_FAILED                -503 /* The error return location should be  */
#define LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT      -504

/* Single Sign-On */
#define LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND         601 /* Federation not found on login */
#define LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED         602
#define LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY        -603 /* Invalid NameIDPolicy in lib:AuthnRequest */
#define LASSO_LOGIN_ERROR_REQUEST_DENIED               604 /* Request denied */
#define LASSO_LOGIN_ERROR_INVALID_SIGNATURE            605
#define LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST       606
#define LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS           607 /* Status code is not success */
#define LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL            608 /* Unknown principal */
#define LASSO_LOGIN_ERROR_NO_DEFAULT_ENDPOINT          609 /* No default endpoint */
#define LASSO_LOGIN_ERROR_ASSERTION_REPLAY             610 /* Assertion replay */

/* Federation Termination Notification */
#define LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER -700 /* Name identifier not found in request */

/* Soap */
#define LASSO_SOAP_FAULT_REDIRECT_REQUEST              800 /* Redirect request from Attribute Provider */
#define LASSO_SOAP_ERROR_MISSING_ENVELOPE             -801 /* Missing SOAP envelope */
#define LASSO_SOAP_ERROR_MISSING_HEADER               -802 /* Missing SOAP header */
#define LASSO_SOAP_ERROR_MISSING_BODY                 -803 /* Missing SOAP body */
#define LASSO_SOAP_ERROR_MISSING_SOAP_FAULT_DETAIL    -804 /* Missing SOAP fault detail */

/* Name Identifier Mapping */
#define LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_NAMESPACE -900 /* Target name space not found */
#define LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE -901
#define LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_IDENTIFIER -902

/* Data Service */
#define LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST    -1000

/* WSF Profile */
#define LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION  -1100
#define LASSO_WSF_PROFILE_ERROR_MISSING_SECURITY     -1101
#define LASSO_WSF_PROFILE_ERROR_MISSING_ASSERTION_ID -1102 /* AssertionID attribute is missing */
#define LASSO_WSF_PROFILE_ERROR_MISSING_ENDPOINT     -1103
#define LASSO_WSF_PROFILE_ERROR_SOAP_FAULT            1104
#define LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM 1105

/* ID-WSF 2 Discovery */
#define LASSO_DISCOVERY_ERROR_SVC_METADATA_REGISTER_FAILED        -1200 /* Service metadata registration failed */
#define LASSO_DISCOVERY_ERROR_SVC_METADATA_ASSOCIATION_ADD_FAILED -1201 /* Service metadata association failed */
#define LASSO_DISCOVERY_ERROR_MISSING_REQUESTED_SERVICE           -1202 /* Missing requested service */
#define LASSO_DISCOVERY_ERROR_FAILED_TO_BUILD_ENDPOINT_REFERENCE  -1203 /* Failed to build Endpoint Reference */

/* ID-WSF 2 Data Service */
#define LASSO_DST_ERROR_MISSING_SERVICE_DATA      -1300 /* Missing service data */
#define LASSO_DST_ERROR_QUERY_FAILED              -1301 /* Query failed */
#define LASSO_DST_ERROR_QUERY_PARTIALLY_FAILED    -1302 /* Query partially failed : some items were correctly processed */
#define LASSO_DST_ERROR_MODIFY_FAILED             -1303 /* Modify failed */
#define LASSO_DST_ERROR_MODIFY_PARTIALLY_FAILED   -1304 /* Modify partially failed : some items were correctly processed */
#define LASSO_DST_ERROR_NEW_DATA_MISSING          -1305 /* Missing new data */

