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

#ifndef __LASSO_PROFILE_H__
#define __LASSO_PROFILE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "identity.h"
#include "server.h"
#include "session.h"

#include "../xml/samlp_request_abstract.h"
#include "../xml/samlp_response_abstract.h"

#define LASSO_TYPE_PROFILE (lasso_profile_get_type())
#define LASSO_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROFILE, LassoProfile))
#define LASSO_PROFILE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PROFILE, LassoProfileClass))
#define LASSO_IS_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROFILE))
#define LASSO_IS_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROFILE))
#define LASSO_PROFILE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PROFILE, LassoProfileClass))

typedef struct _LassoProfile LassoProfile;
typedef struct _LassoProfileClass LassoProfileClass;
typedef struct _LassoProfilePrivate LassoProfilePrivate;

/**
 * LassoRequestType:
 * @LASSO_REQUEST_TYPE_INVALID: invalid
 * @LASSO_REQUEST_TYPE_LOGIN: Single Sign On and Federation
 * @LASSO_REQUEST_TYPE_LOGOUT: Single Logout
 * @LASSO_REQUEST_TYPE_DEFEDERATION: Federation Termination
 * @LASSO_REQUEST_TYPE_NAME_REGISTRATION: Name Registration
 * @LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING: Name Identifier Mapping
 * @LASSO_REQUEST_TYPE_LECP: Liberty-Enabled Client / Proxy
 * @LASSO_REQUEST_TYPE_DISCO_QUERY: ID-WSF 1.0 Discovery Query request
 * @LASSO_REQUEST_TYPE_DISCO_MODIFY: ID-WSF 1.0 Discovery Modify Request
 * @LASSO_REQUEST_TYPE_DST_QUERY: ID-WSF 1.0 Data Service Template Query request
 * @LASSO_REQUEST_TYPE_DST_MODIFY: ID-WSF 1.0 Data Service Temaplte Modify request
 * @LASSO_REQUEST_TYPE_SASL_REQUEST: ID-WSF 1.0 Authentication request
 * @LASSO_REQUEST_TYPE_NAME_ID_MANAGEMENT: SAML 2.0 NameID Management request
 * @LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_REGISTER: ID-WSF 2.0 Discovery Service Metadata Register
 * request
 * @LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_ASSOCIATION_ADD: ID-WSF 2.0 Discovery Service Metadata
 * Add Association request
 * @LASSO_REQUEST_TYPE_IDWSF2_DISCO_QUERY: ID-WSF 2.0 Discovery Query request
 *
 * Request types (known for SOAP endpoints)
 */
typedef enum {
	LASSO_REQUEST_TYPE_INVALID = 0,
	LASSO_REQUEST_TYPE_LOGIN = 1,
	LASSO_REQUEST_TYPE_LOGOUT = 2,
	LASSO_REQUEST_TYPE_DEFEDERATION = 3,
	LASSO_REQUEST_TYPE_NAME_REGISTRATION = 4,
	LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING = 5,
	LASSO_REQUEST_TYPE_LECP = 6,
	LASSO_REQUEST_TYPE_DISCO_QUERY = 7,
	LASSO_REQUEST_TYPE_DISCO_MODIFY = 8,
	LASSO_REQUEST_TYPE_DST_QUERY = 9,
	LASSO_REQUEST_TYPE_DST_MODIFY = 10,
	LASSO_REQUEST_TYPE_SASL_REQUEST = 11,
	LASSO_REQUEST_TYPE_NAME_ID_MANAGEMENT = 12,
	LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_REGISTER = 13,
	LASSO_REQUEST_TYPE_IDWSF2_DISCO_SVCMD_ASSOCIATION_ADD = 14,
	LASSO_REQUEST_TYPE_IDWSF2_DISCO_QUERY = 15
} LassoRequestType;

/**
 * LassoProfileSignatureHint:
 * @LASSO_PROFILE_SIGNATURE_HINT_MAYBE: let Lasso decide what to do.
 * @LASSO_PROFILE_SIGNATURE_HINT_FORCE: generate and validate all signatures.
 * @LASSO_PROFILE_SIGNATURE_HINT_FORBID: do not generate or validate any signature.
 *
 * Advice a #LassoProfile object about the policy for generating request and response
 * signatures.
 */
typedef enum {
	LASSO_PROFILE_SIGNATURE_HINT_MAYBE  = 0,
	LASSO_PROFILE_SIGNATURE_HINT_FORCE  = 1,
	LASSO_PROFILE_SIGNATURE_HINT_FORBID = 2
} LassoProfileSignatureHint;

/**
 * LassoProfileSignatureVerifyHint:
 * @LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE: let Lasso decide what to do.
 * @LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE: always check signatures.
 * @LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE: check signatures but do not stop protocol handling
 * on failures. The result of signature checking is still available in
 * #LassoProfile.signature_status
 *
 * Advice a #LassoProfile object about the policy checking request and response
 * signatures.
 */
typedef enum {
	LASSO_PROFILE_SIGNATURE_VERIFY_HINT_MAYBE = 0,
	LASSO_PROFILE_SIGNATURE_VERIFY_HINT_FORCE = 1,
	LASSO_PROFILE_SIGNATURE_VERIFY_HINT_IGNORE = 2,
	LASSO_PROFILE_SIGNATURE_VERIFY_HINT_LAST
} LassoProfileSignatureVerifyHint;

/**
 * LassoProfile:
 * @server: #LassoServer object representing the provider intiating this profile,
 * @request: the currently initialized request, or the last request parsed,
 * @response: the currently intialized request, or the last response parsed,
 * @nameIdentifier: for profiles which transmit a name identifier (that is, most of them), the
 * parsed name identifier, can be a #LassoSamlNameIdentifier or a #LassoSaml2NameID,
 * @remote_providerID: the provider ID of the issuer of the last parsed message, whatever it is (a
 * request or a response),
 * @msg_url: when generating a request or a response, it give the URL to contact
 * @msg_body: when generating a request or a response using HTTP POST binding (can be HTTP-SOAP or
 * HTTP-Post binding), the body of the POST will be in this field,
 * @msg_relayState: put there the relaystate to put in the genereated URL for HTTP-Redirect or
 * HTTP-Get binding.
 * @signature_status: result of the last signature validation.
 * @identity: the state of federation linking for the current user.
 * @session: the state of global SSO session for the current user.
 *
 * #LassoProfile, child class of #LassoNode is the basis object of profiles object like #LassoLogin, #LassoLogout,
 * #LassoDefederation, #LassoNameIdentifierMapping, #LassoNameRegistration, #LassoNameIdManagement
 * or #LassoAssertionQuery. It handles the minimal state used by all theses profiles.
 */
struct _LassoProfile {
	LassoNode parent;

	/*< public >*/
	LassoServer *server;

	LassoNode *request;
	LassoNode *response;

	LassoNode *nameIdentifier;

	gchar *remote_providerID;

	gchar *msg_url;
	gchar *msg_body;
	gchar *msg_relayState;

	/*< private >*/
	LassoIdentity *identity;
	LassoSession  *session;

	LassoHttpMethod http_request_method;
	gint signature_status;

	LassoProfilePrivate *private_data;
};

struct _LassoProfileClass {
	LassoNodeClass parent;
};

/* public functions */

LASSO_EXPORT LassoRequestType lasso_profile_get_request_type_from_soap_msg(const gchar *soap);
LASSO_EXPORT gboolean lasso_profile_is_liberty_query(const gchar *query);


/* public methods */

LASSO_EXPORT GType lasso_profile_get_type(void);

LASSO_EXPORT LassoIdentity* lasso_profile_get_identity(LassoProfile *profile);
LASSO_EXPORT LassoSession* lasso_profile_get_session(LassoProfile *profile);
LASSO_EXPORT gboolean lasso_profile_is_identity_dirty(LassoProfile *profile);
LASSO_EXPORT gboolean lasso_profile_is_session_dirty(LassoProfile *profile);

LASSO_EXPORT lasso_error_t lasso_profile_set_identity_from_dump(LassoProfile *profile, const gchar *dump);
LASSO_EXPORT lasso_error_t lasso_profile_set_session_from_dump(LassoProfile *profile, const gchar *dump);
LASSO_EXPORT LassoNode* lasso_profile_get_nameIdentifier(LassoProfile *profile);

LASSO_EXPORT char* lasso_profile_get_artifact(LassoProfile *profile);
LASSO_EXPORT char* lasso_profile_get_artifact_message(LassoProfile *profile);
LASSO_EXPORT void  lasso_profile_set_artifact_message(LassoProfile *profile, const char *message);
LASSO_EXPORT LassoServer* lasso_profile_get_server(LassoProfile *profile);
LASSO_EXPORT void lasso_profile_set_signature_hint(LassoProfile *profile,
		LassoProfileSignatureHint signature_hint);
LASSO_EXPORT LassoProfileSignatureHint lasso_profile_get_signature_hint(LassoProfile *profile);
LASSO_EXPORT lasso_error_t lasso_profile_set_soap_fault_response(LassoProfile *profile, const char
		*faultcode, const char *faultstring, GList *details);
LASSO_EXPORT void lasso_profile_set_signature_verify_hint(LassoProfile *profile,
		LassoProfileSignatureVerifyHint signature_verify_hint);
LASSO_EXPORT LassoProfileSignatureVerifyHint lasso_profile_get_signature_verify_hint(LassoProfile *profile);
LASSO_EXPORT LassoProviderRole lasso_profile_sso_role_with(LassoProfile *profile,
		const char *remote_provider_id);
LASSO_EXPORT lasso_error_t lasso_profile_get_signature_status(LassoProfile *profile);
LASSO_EXPORT char* lasso_profile_get_issuer(const char *message);
LASSO_EXPORT char* lasso_profile_get_in_response_to(const char *message);

LASSO_EXPORT char* lasso_profile_get_message_id(LassoProfile *profile);
LASSO_EXPORT void lasso_profile_set_message_id(LassoProfile *profile, const char *message_id);

LASSO_EXPORT LassoNode* lasso_profile_get_idp_list(LassoProfile *profile);
LASSO_EXPORT void lasso_profile_set_idp_list(LassoProfile *profile, const LassoNode *idp_list);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROFILE_H__ */
