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

#include <glib.h>
#include "errors.h"
#include "xml/xml.h"

/* WARNING!!!: This is a generated file do not modify it, add new error message
 * a comments inside errors.h */

/**
 * lasso_strerror:
 * @error_code: a gint error code returned by a lasso function
 *
 * Convert an error code from a lasso fuction to a human readable string.
 *
 * Returns: a static string.
 */
const char*
lasso_strerror(int error_code)
{
	switch (error_code) {
		case LASSO_ASSERTION_QUERY_ERROR_ATTRIBUTE_REQUEST_ALREADY_EXIST:
			return "Tried to add the same attribute request a second time.";
		case LASSO_ASSERTION_QUERY_ERROR_NOT_AN_ATTRIBUTE_QUERY:
			return "The current assertion query does not contain an attribute query.";
		case LASSO_DATA_SERVICE_ERROR_CANNOT_ADD_ITEM:
			return "LASSO_DATA_SERVICE_ERROR_CANNOT_ADD_ITEM";
		case LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST:
			return "LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST";
		case LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER:
			return "Name identifier not found in request";
		case LASSO_DISCOVERY_ERROR_FAILED_TO_BUILD_ENDPOINT_REFERENCE:
			return "Failed to build Endpoint Reference";
		case LASSO_DISCOVERY_ERROR_MISSING_REQUESTED_SERVICE:
			return "Missing requested service";
		case LASSO_DISCOVERY_ERROR_SVC_METADATA_ASSOCIATION_ADD_FAILED:
			return "Service metadata association failed";
		case LASSO_DISCOVERY_ERROR_SVC_METADATA_REGISTER_FAILED:
			return "Service metadata registration failed";
		case LASSO_DST_ERROR_EMPTY_REQUEST:
			return "Request is empty.";
		case LASSO_DST_ERROR_MALFORMED_QUERY:
			return "QueryObject is malformed";
		case LASSO_DST_ERROR_MISSING_SERVICE_DATA:
			return "Missing service data";
		case LASSO_DST_ERROR_MODIFY_FAILED:
			return "Modify failed";
		case LASSO_DST_ERROR_MODIFY_PARTIALLY_FAILED:
			return "Modify partially failed : some items were correctly processed";
		case LASSO_DST_ERROR_NEW_DATA_MISSING:
			return "Missing new data";
		case LASSO_DST_ERROR_NO_DATA:
			return "No data or no data for the designated query item in the query response";
		case LASSO_DST_ERROR_QUERY_FAILED:
			return "Query failed";
		case LASSO_DST_ERROR_QUERY_NOT_FOUND:
			return "Looked query is not found";
		case LASSO_DST_ERROR_QUERY_PARTIALLY_FAILED:
			return "Query partially failed : some items were correctly processed";
		case LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED:
			return "LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED";
		case LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED:
			return "Failed to load certificate.";
		case LASSO_DS_ERROR_CONTEXT_CREATION_FAILED:
			return "Failed to create signature context.";
		case LASSO_DS_ERROR_DECRYPTION_FAILED:
			return "Decryption of an encrypted node failed";
		case LASSO_DS_ERROR_DECRYPTION_FAILED_MISSING_PRIVATE_KEY:
			return "Could not decrypt because the private key is not present.";
		case LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED:
			return "Computation of an SHA1 digest failed.";
		case LASSO_DS_ERROR_ENCRYPTION_FAILED:
			return "Creation of an encrypted node failed";
		case LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML:
			return "SAML signature reference must be to a Request, a Reponse or an Assertion ID attribute";
		case LASSO_DS_ERROR_INVALID_SIGALG:
			return "Invalid signature algorithm.";
		case LASSO_DS_ERROR_INVALID_SIGNATURE:
			return "Invalid signature.";
		case LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED:
			return "Failed to create keys manager.";
		case LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED:
			return "Failed to initialize keys manager.";
		case LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED:
			return "Failed to load private key.";
		case LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED:
			return "Failed to load public key.";
		case LASSO_DS_ERROR_SIGNATURE_FAILED:
			return "Failed to sign the node.";
		case LASSO_DS_ERROR_SIGNATURE_NOT_FOUND:
			return "Signature element not found.";
		case LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND:
			return "Signature template has not been found.";
		case LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED:
			return "LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED";
		case LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED:
			return "Failed to verify signature.";
		case LASSO_DS_ERROR_TOO_MUCH_REFERENCES:
			return "SAML signature must contain only one reference";
		case LASSO_ERROR_CAST_FAILED:
			return "Expected GObject class was not found, cast failed";
		case LASSO_ERROR_OUT_OF_MEMORY:
			return "Out of memory";
		case LASSO_ERROR_UNDEFINED:
			return "Undefined error.";
		case LASSO_ERROR_UNIMPLEMENTED:
			return "Unimplemented part of Lasso.";
		case LASSO_IDWSF2_DISCOVERY_ERROR_DUPLICATE:
			return "Last discovery request was denied because it would result in duplicate data in the service";
		case LASSO_IDWSF2_DISCOVERY_ERROR_FAILED:
			return "Last discovery request failed.";
		case LASSO_IDWSF2_DISCOVERY_ERROR_FORBIDDEN:
			return "Last discovery request is forbidden by policy.";
		case LASSO_IDWSF2_DISCOVERY_ERROR_LOGICAL_DUPLICATE:
			return "Last discovery request was denied because it would result in logically duplicate data in the service";
		case LASSO_IDWSF2_DISCOVERY_ERROR_NOT_FOUND:
			return "The specified item(s) were not found.";
		case LASSO_IDWSF2_DISCOVERY_ERROR_NO_RESULTS:
			return "The discovery query had no matching results.";
		case LASSO_IDWSF2_DST_ERROR_DUPLICATE_ITEM:
			return "A call to add a new item would result in duplicate items.";
		case LASSO_IDWSF2_DST_ERROR_ITEM_NOT_FOUND:
			return "The item_id was not found in the current query request.";
		case LASSO_IDWSF2_DST_ERROR_PARTIAL_FAILURE:
			return "Server responded with a partial failure status code.";
		case LASSO_IDWSF2_DST_ERROR_UNKNOWN_STATUS_CODE:
			return "Server response with an unknown status code.";
		case LASSO_LOGIN_ERROR_ASSERTION_DOES_NOT_MATCH_REQUEST_ID:
			return "If inResponseTo attribute is present, a matching request must be present too in the LassoLogin object";
		case LASSO_LOGIN_ERROR_ASSERTION_REPLAY:
			return "Assertion replay";
		case LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED:
			return "Consent of the principal was not obtained.";
		case LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND:
			return "Federation not found on login";
		case LASSO_LOGIN_ERROR_INVALID_ASSERTION_SIGNATURE:
			return "Signature on an assertion could not be verified.";
		case LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY:
			return "Invalid NameIDPolicy in lib:AuthnRequest";
		case LASSO_LOGIN_ERROR_INVALID_SIGNATURE:
			return "The signature of a message or of an assertion is invalid. That is badly computed or with an unknown key.";
		case LASSO_LOGIN_ERROR_NO_DEFAULT_ENDPOINT:
			return "No default endpoint";
		case LASSO_LOGIN_ERROR_REQUEST_DENIED:
			return "Request denied.";
		case LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS:
			return "Status code is not success";
		case LASSO_LOGIN_ERROR_UNKNOWN_PRINCIPAL:
			return "Unknown principal";
		case LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST:
			return "An unsigned authn request was received but the metadata specify that they must be signed.";
		case LASSO_LOGOUT_ERROR_FEDERATION_NOT_FOUND:
			return "Federation not found on logout";
		case LASSO_LOGOUT_ERROR_PARTIAL_LOGOUT:
			return "Logout could not be propagated to every service provider in the current session.";
		case LASSO_LOGOUT_ERROR_REQUEST_DENIED:
			return "Request denied by identity provider";
		case LASSO_LOGOUT_ERROR_UNKNOWN_PRINCIPAL:
			return "Unknown principal on logout";
		case LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE:
			return "Unsupported protocol profile";
		case LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE:
			return "LASSO_NAME_IDENTIFIER_MAPPING_ERROR_FORBIDDEN_CALL_ON_THIS_SIDE";
		case LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_IDENTIFIER:
			return "LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_IDENTIFIER";
		case LASSO_NAME_IDENTIFIER_MAPPING_ERROR_MISSING_TARGET_NAMESPACE:
			return "Target name space not found";
		case LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ:
			return "An object type provided as parameter is invalid or object is NULL.";
		case LASSO_PARAM_ERROR_CHECK_FAILED:
			return "The error return location should be either NULL or contains a NULL error.";
		case LASSO_PARAM_ERROR_INVALID_VALUE:
			return "A parameter value is invalid.";
		case LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT:
			return "The call failed because an argument is a partially-initialized object.";
		case LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP:
			return "Failed to create identity from dump";
		case LASSO_PROFILE_ERROR_BAD_SESSION_DUMP:
			return "Failed to create session from dump";
		case LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED:
			return "Error building request message";
		case LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED:
			return "Error building request QUERY url";
		case LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED:
			return "Error building request object";
		case LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED:
			return "Error building response object";
		case LASSO_PROFILE_ERROR_CANNOT_FIND_A_PROVIDER:
			return "Profile was called without a specific provider and we cannot find one.";
		case LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE:
			return "The profile cannot verify a signature on the message";
		case LASSO_PROFILE_ERROR_ENDPOINT_INDEX_NOT_FOUND:
			return "A received artifact contains an andpoint index which does not exist in the metadata of the corresponding provider.";
		case LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND:
			return "Federation not found";
		case LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND:
			return "Identity not found";
		case LASSO_PROFILE_ERROR_INVALID_ARTIFACT:
			return "Invalid artifact";
		case LASSO_PROFILE_ERROR_INVALID_ASSERTION:
			return "The assertion is malformed, Issuer differs from NameQualifier of the subject, signature cannot be verified.";
		case LASSO_PROFILE_ERROR_INVALID_ASSERTION_CONDITIONS:
			return "An assertion conditions could not be validated.";
		case LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD:
			return "Invalid HTTP method";
		case LASSO_PROFILE_ERROR_INVALID_ISSUER:
			return "Assertion issuer is not the same as the requested issuer";
		case LASSO_PROFILE_ERROR_INVALID_MSG:
			return "Invalid message";
		case LASSO_PROFILE_ERROR_INVALID_POST_MSG:
			return "Invalid POST message";
		case LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE:
			return "Invalid protocol profile";
		case LASSO_PROFILE_ERROR_INVALID_QUERY:
			return "Invalid URL query";
		case LASSO_PROFILE_ERROR_INVALID_REQUEST:
			return "Received request is not of the expected type.";
		case LASSO_PROFILE_ERROR_INVALID_RESPONSE:
			return "Received request is not of the expected type.";
		case LASSO_PROFILE_ERROR_INVALID_SOAP_MSG:
			return "Invalid SOAP message";
		case LASSO_PROFILE_ERROR_ISSUER_IS_NOT_AN_IDP:
			return "The issuer of an assertion is not considered as an IdP";
		case LASSO_PROFILE_ERROR_MISSING_ARTIFACT:
			return "Missing SAML artifact";
		case LASSO_PROFILE_ERROR_MISSING_ASSERTION:
			return "When looking for an assertion we did not found it.";
		case LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY:
			return "Found an encrypted element but encryption private key is not set";
		case LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE:
			return "Missing endpoint reference";
		case LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE_ADDRESS:
			return "Missing endpoint reference address";
		case LASSO_PROFILE_ERROR_MISSING_ISSUER:
			return "Missing issuer";
		case LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER:
			return "Missing name identifier";
		case LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID:
			return "ProviderID not found";
		case LASSO_PROFILE_ERROR_MISSING_REQUEST:
			return "Missing request";
		case LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING:
			return "Missing ressource offering";
		case LASSO_PROFILE_ERROR_MISSING_RESPONSE:
			return "Missing response";
		case LASSO_PROFILE_ERROR_MISSING_SERVER:
			return "No server object set in the profile";
		case LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION:
			return "Missing service description";
		case LASSO_PROFILE_ERROR_MISSING_SERVICE_INSTANCE:
			return "Missing service instance";
		case LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE:
			return "Missing service type";
		case LASSO_PROFILE_ERROR_MISSING_STATUS_CODE:
			return "Missing status code";
		case LASSO_PROFILE_ERROR_MISSING_SUBJECT:
			return "Missing subject";
		case LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND:
			return "Name identifier not found";
		case LASSO_PROFILE_ERROR_REQUEST_DENIED:
			return "Generic error when an IdP or an SP return the RequestDenied status code in its response.";
		case LASSO_PROFILE_ERROR_RESPONSE_DOES_NOT_MATCH_REQUEST:
			return "Received response does not refer to the request sent";
		case LASSO_PROFILE_ERROR_SESSION_NOT_FOUND:
			return "Session not found";
		case LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS:
			return "Status code is not success";
		case LASSO_PROFILE_ERROR_UNKNOWN_ISSUER:
			return "The issuer of an assertion is unkown to us.";
		case LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL:
			return "Unable to find Profile URL in metadata";
		case LASSO_PROFILE_ERROR_UNKNOWN_PROVIDER:
			return "@Deprecated: Since 2.2.3 The issuer of the message is unknown to us";
		case LASSO_PROFILE_ERROR_UNSUPPORTED_BINDING:
			return "The responder reported that he does not support this binding";
		case LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE:
			return "Unsupported protocol profile";
		case LASSO_PROVIDER_ERROR_MISSING_PUBLIC_KEY:
			return "The provider has no known public key";
		case LASSO_REGISTRY_ERROR_KEY_EXISTS:
			return "Key alreadys exists in the registry";
		case LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED:
			return "Failed to add new provider.";
		case LASSO_SERVER_ERROR_ADD_PROVIDER_PROTOCOL_MISMATCH:
			return "Failed to add new provider (protocol mismatch). It means that you tried to add a provider supporting a protocol imcompatible with the protocol declared for your #LassoServer, for example metadata for ID-FF 1.2 with metadata for SAML 2.0.";
		case LASSO_SERVER_ERROR_INVALID_XML:
			return "Parsed XML is invalid.";
		case LASSO_SERVER_ERROR_NO_PROVIDER_LOADED:
			return "When loading a metadata file it indicates that no provider could be loaded. It could be because the file is not well formed, or because there is no provider for the role sought.";
		case LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND:
			return "The identifier of a provider is unknown to #LassoServer. To register a provider in a #LassoServer object, you must use the methods lasso_server_add_provider() or lasso_server_add_provider_from_buffer().";
		case LASSO_SERVER_ERROR_SET_ENCRYPTION_PRIVATE_KEY_FAILED:
			return "Failed to load encryption private key.";
		case LASSO_SOAP_ERROR_MISSING_BODY:
			return "Missing SOAP body";
		case LASSO_SOAP_ERROR_MISSING_ENVELOPE:
			return "Missing SOAP envelope";
		case LASSO_SOAP_ERROR_MISSING_HEADER:
			return "Missing SOAP header";
		case LASSO_SOAP_ERROR_MISSING_SOAP_FAULT_DETAIL:
			return "Missing SOAP fault detail";
		case LASSO_SOAP_ERROR_REDIRECT_REQUEST_FAULT:
			return "A SOAP Fault containing a Redirect Request was received";
		case LASSO_WSF_PROFILE_ERROR_INVALID_OR_MISSING_REFERENCE_TO_MESSAGE_ID:
			return "refToMessageID attribute of the Corrrelation header does not match the SOAP request";
		case LASSO_WSF_PROFILE_ERROR_MISSING_ASSERTION_ID:
			return "AssertionID attribute is missing";
		case LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION:
			return "Correlation SOAP Header is missing";
		case LASSO_WSF_PROFILE_ERROR_MISSING_CREDENTIAL_REF:
			return "WS-Security SAML Token secmech needs a CredentialRef";
		case LASSO_WSF_PROFILE_ERROR_MISSING_DESCRIPTION:
			return "No ID-WSF web Service description could be found for the current security mechanism";
		case LASSO_WSF_PROFILE_ERROR_MISSING_ENDPOINT:
			return "Cannot find an WSP endpoint for the ID-WSF service";
		case LASSO_WSF_PROFILE_ERROR_MISSING_RESOURCE_ID:
			return "The necessary ResourceID or EncryptedResourceID for calling an ID-WSF service is missing.";
		case LASSO_WSF_PROFILE_ERROR_MISSING_SECURITY:
			return "Security SOAP Header is missing";
		case LASSO_WSF_PROFILE_ERROR_MISSING_SENDER_ID:
			return "The received ID-WSF request miss a Sender id.";
		case LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST:
			return "The last parsed response contained a SOAP fault with a RedirectRequest element.";
		case LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST_UNSUPPORTED_BY_REQUESTER:
			return "The requester does not support SOAP Fault containing RedirectRequest elements. So it is not possible to use lasso_idwsf2_profile_redirect_user_for_interaction().";
		case LASSO_WSF_PROFILE_ERROR_SECURITY_MECHANISM_CHECK_FAILED:
			return "Check for a security mechanism upon a received request failed.";
		case LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED:
			return "A interaction is required but the sender did not allow use to make interact redirect requests.";
		case LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED_FOR_DATA:
			return "A interaction is required to get fresh datas but the sender did not allow use to make interact redirect requests.";
		case LASSO_WSF_PROFILE_ERROR_SOAP_FAULT:
			return "SOAP ID-WSF binding returned a SOAP fault";
		case LASSO_WSF_PROFILE_ERROR_UNKNOWN_STATUS_CODE:
			return "A response contained an unknown status code.";
		case LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM:
			return "The specified security mechanism is not supported by lasso ID-WSF library";
		case LASSO_WSSEC_ERROR_BAD_PASSWORD:
			return "The known password does not match the UsernameToken";
		case LASSO_WSSEC_ERROR_MISSING_SECURITY_TOKEN:
			return "The request miss a WS-Security token.";
		case LASSO_XMLENC_ERROR_INVALID_ENCRYPTED_DATA:
			return "The EncryptedData node is invalid, look at the logs.";
		case LASSO_XML_ERROR_ATTR_NOT_FOUND:
			return "Unable to get attribute of element.";
		case LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND:
			return "Unable to get attribute value of element.";
		case LASSO_XML_ERROR_INVALID_FILE:
			return "Invalid XML file";
		case LASSO_XML_ERROR_MISSING_NAMESPACE:
			return "A namespace is missing.";
		case LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND:
			return "Unable to get content of element.";
		case LASSO_XML_ERROR_NODE_NOT_FOUND:
			return "Unable to get child of element.";
		case LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED:
			return "Construction of an object from an XML document failed.";
		case LASSO_XML_ERROR_SCHEMA_INVALID_FRAGMENT:
			return "An XML tree does not respect at least an XML schema of its namespaces.";
		default:
			return "Unknown LASSO_ERROR, you should regenerate errors.c";
	}
}
