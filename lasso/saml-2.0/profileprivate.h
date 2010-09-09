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

#ifndef __LASSO_SAML20_PROFILE_PRIVATE_H__
#define __LASSO_SAML20_PROFILE_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/profile.h"
#include "../xml/saml-2.0/saml2_name_id.h"
#include "../xml/saml-2.0/saml2_encrypted_element.h"
#include "../xml/saml-2.0/samlp2_status_response.h"
#include "../xml/saml-2.0/samlp2_request_abstract.h"
#include "../xml/saml-2.0/saml2_subject.h"
#include "../id-ff/provider.h"

int lasso_saml20_profile_init_request(LassoProfile *profile, const char *remote_provider_id,
		gboolean first_in_session, LassoSamlp2RequestAbstract *request_abstract,
		LassoHttpMethod http_method, LassoMdProtocolType protocol_type);
#define lasso_saml20_profile_set_response_status_success(profile, code2) \
	lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_SUCCESS, code2)
#define lasso_saml20_profile_set_response_status_responder(profile, code2) \
	lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_RESPONDER, code2)
#define lasso_saml20_profile_set_response_status_requester(profile, code2) \
	lasso_saml20_profile_set_response_status(profile, LASSO_SAML2_STATUS_CODE_REQUESTER, code2)

int lasso_saml20_profile_set_response_status(LassoProfile *profile, const char *code1, const char
		*code2);
int lasso_saml20_profile_init_artifact_resolve(LassoProfile *profile,
		const char *msg, LassoHttpMethod method);
int lasso_saml20_profile_process_artifact_resolve(LassoProfile *profile, const char *msg);
int lasso_saml20_profile_build_artifact_response(LassoProfile *profile);
int lasso_saml20_profile_process_artifact_response(LassoProfile *profile, const char *msg);
gint lasso_saml20_profile_set_session_from_dump(LassoProfile *profile);
gint lasso_saml20_profile_process_name_identifier_decryption(LassoProfile *profile,
		LassoSaml2NameID **name_id, LassoSaml2EncryptedElement **encrypted_id);
int lasso_saml20_profile_process_soap_request(LassoProfile *profile, const char *request_msg);
int lasso_saml20_profile_process_soap_response(LassoProfile *profile, const char *response_msg);
int lasso_saml20_profile_process_any_request(LassoProfile *profile, LassoNode *request_node,
	const char *request_msg);
int lasso_saml20_profile_process_any_response(LassoProfile *profile, LassoSamlp2StatusResponse *response_node, LassoHttpMethod *response_method, const char *response_msg);
int lasso_saml20_profile_setup_request_signing(LassoProfile *profile);
int lasso_saml20_profile_build_request_msg(LassoProfile *profile, const char *service, LassoHttpMethod method, const char *url);
int lasso_saml20_profile_build_response_msg(LassoProfile *profile, char *service,
		LassoHttpMethod method, const char *_url);
int lasso_saml20_profile_init_response(LassoProfile *profile,
		LassoSamlp2StatusResponse *status_response, const char *status_code1, const char *status_code2);
int lasso_saml20_profile_validate_request(LassoProfile *profile, gboolean needs_identity, LassoSamlp2StatusResponse *status_response, LassoProvider **provider_out);
gint lasso_saml20_profile_build_http_redirect_query_simple(LassoProfile *profile, LassoNode *msg,
		const char *profile_name, gboolean is_response);
gint lasso_saml20_profile_build_http_redirect(LassoProfile *profile, LassoNode *msg,
		const char *url);
gint lasso_profile_saml20_setup_message_signature(LassoProfile *profile,
		LassoNode *request_or_response);
gint lasso_saml20_profile_setup_encrypted_node(LassoProvider *provider,
		LassoNode **node_to_encrypt, LassoNode **node_destination);
int lasso_saml20_profile_setup_subject(LassoProfile *profile, LassoSaml2Subject *subject);
int lasso_saml20_profile_check_signature_status(LassoProfile *profile);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML20_PROFILE_PRIVATE_H__ */
