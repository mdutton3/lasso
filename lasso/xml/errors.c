/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <glib/gstrfuncs.h>
#include <lasso/xml/errors.h>

const char*
lasso_strerror(int error_code)
{
	switch (error_code) {
		case LASSO_XML_ERROR_NODE_NOT_FOUND:
			return "Unable to get '%s' child of '%s' element.";
		case LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND:
			return "Unable to get content of '%s' element.";
		case LASSO_XML_ERROR_ATTR_NOT_FOUND:
			return "Unable to get '%s' attribute of '%s' element.";
		case LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND:
			return "Unable to get '%s' attribute value of '%s' element.";
		case LASSO_DS_ERROR_SIGNATURE_NOT_FOUND:
			return "Signature element not found in %s.";
		case LASSO_DS_ERROR_INVALID_SIGNATURE:
			return "The signature of %s is invalid.";
		case LASSO_DS_ERROR_CONTEXT_CREATION_FAILED:
			return "Failed to create signature context.";
		case LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED:
			return "Failed to load public key %s.";
		case LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED:
			return "Failed to load private key %s.";
		case LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED:
			return "Failed to load certificate %s.";
		case LASSO_DS_ERROR_SIGNATURE_FAILED:
			return "Failed to sign the node %s.";
		case LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED:
			return "Failed to create keys manager.";
		case LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED:
			return "Failed to initialize keys manager.";
		case LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED:
			return "Failed to verify signature of %s.";
		case LASSO_DS_ERROR_INVALID_SIGALG:
			return "Invalid signature algorithm.";

		case LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND:
			return "Failed to get LassoProvider object "\
				"with providerID %s in LassoServer object.";
		case LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED:
			return "Failed to add new provider.";

		case LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE:
			return "Unsupported logout protocol profile";
		case LASSO_PROFILE_ERROR_INVALID_QUERY:
			return "Invalid URL query";
		case LASSO_PROFILE_ERROR_INVALID_POST_MSG:
			return "Invalid POST message";
		case LASSO_PROFILE_ERROR_INVALID_SOAP_MSG:
			return "Invalid SOAP message";
		case LASSO_PROFILE_ERROR_MISSING_REQUEST:
			return "Missing request";
		case LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD:
			return "Invalid HTTP method";
		case LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE:
			return "Invalid protocol profile";
		case LASSO_PROFILE_ERROR_INVALID_MSG:
			return "Invalid message";
		case LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID:
			return "ProviderID not found";
		case LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE:
			return "Unsupported protocol profile";
		case LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL:
			return "Unable to find Profile URL in metadata";
		case LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND:
			return "Identity not found";
		case LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND:
			return "Federation not found";
		case LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND:
			return "Name identifier not found";
		case LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED:
			return "Error building request QUERY url";
		case LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED:
			return "Error building request object";
		case LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED:
			return "Error building request message";
		case LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED:
			return "Error building response object";
		case LASSO_PROFILE_ERROR_SESSION_NOT_FOUND:
			return "Session not found";
		case LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP:
			return "Failed to create identity from dump";
		case LASSO_PROFILE_ERROR_BAD_SESSION_DUMP:
			return "Failed to create session from dump";

		case LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ:
			return "An object type provided as parameter "\
				"is invalid or object is NULL.";
		case LASSO_PARAM_ERROR_INVALID_VALUE:
			return "A parameter value is invalid.";
		case LASSO_PARAM_ERROR_CHECK_FAILED:
			return "The error return location should be "\
				"either NULL or contains a NULL error.";

		case LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY:
			return "Invalid NameIDPolicy in lib:AuthnRequest: %s";

		case LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER:
			return "Name identifier not found in request";

		default:
			return g_strdup_printf("Undefined error code %d.", error_code);
	}
}
