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

/* Negative errors : programming or runtime recoverable errors */
/* Positive errors : Liberty Alliance recoverable errors */

/* undefined */
#define LASSO_ERROR_UNDEFINED                           -1

/* generic XML */
#define LASSO_XML_ERROR_NODE_NOT_FOUND                 -10
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND         -11
#define LASSO_XML_ERROR_ATTR_NOT_FOUND                 -12
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND           -13

/* XMLDSig */
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND             101
#define LASSO_DS_ERROR_INVALID_SIGNATURE               102
#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -103
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED        -104
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED         -105
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED        -106
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED        -107
#define LASSO_DS_ERROR_SIGNATURE_FAILED               -108
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED      -109
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED          -110
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED  -111
#define LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED      -112
#define LASSO_DS_ERROR_INVALID_SIGALG                 -113
#define LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED          -114
#define LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND   -115

/* Server */
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND         -201
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED        -202

/* Single Logout */
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE        -301

/* Profile */
#define LASSO_PROFILE_ERROR_INVALID_QUERY             -401
#define LASSO_PROFILE_ERROR_INVALID_POST_MSG          -402
#define LASSO_PROFILE_ERROR_INVALID_SOAP_MSG          -403
#define LASSO_PROFILE_ERROR_MISSING_REQUEST           -404
#define LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD       -405
#define LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE   -406
#define LASSO_PROFILE_ERROR_INVALID_MSG               -407
#define LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID -408
#define LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE       -409
#define LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL       -410
#define LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND        -411
#define LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND      -412
#define LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND -413
#define LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED     -414
#define LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED   -415
#define LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED   -416
#define LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED  -417
#define LASSO_PROFILE_ERROR_SESSION_NOT_FOUND         -418
#define LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP         -419
#define LASSO_PROFILE_ERROR_BAD_SESSION_DUMP          -420

/* functions/methods parameters checking */
#define LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ        -501
#define LASSO_PARAM_ERROR_INVALID_VALUE               -502
#define LASSO_PARAM_ERROR_CHECK_FAILED                -503

/* Single Sign-On */
#define LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND		 601
#define LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED		 602
#define LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY		-603
#define LASSO_LOGIN_ERROR_REQUEST_DENIED		 604
#define LASSO_LOGIN_ERROR_INVALID_SIGNATURE		 605
#define LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST	 606
#define LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS             607

/* Federation Termination Notification */
#define LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER  -700

