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

#ifndef __LASSO_SAML20_LOGIN_PRIVATE_H__
#define __LASSO_SAML20_LOGIN_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/login.h"

gint lasso_saml20_login_init_authn_request(LassoLogin *login, LassoHttpMethod http_method);
gint lasso_saml20_login_build_authn_request_msg(LassoLogin *login);
gint lasso_saml20_login_build_authn_response_msg(LassoLogin *login);
gint lasso_saml20_login_process_authn_request_msg(LassoLogin *login, const char *authn_request_msg);
gboolean lasso_saml20_login_must_authenticate(LassoLogin *login);
gboolean lasso_saml20_login_must_ask_for_consent(LassoLogin *login);
int lasso_saml20_login_validate_request_msg(LassoLogin *login, gboolean authentication_result,
		gboolean is_consent_obtained);
int lasso_saml20_login_build_assertion(LassoLogin *login,
		const char *authenticationMethod, const char *authenticationInstant,
		const char *notBefore, const char *notOnOrAfter);
gint lasso_saml20_login_build_artifact_msg(LassoLogin *login, LassoHttpMethod http_method);
gint lasso_saml20_login_init_request(LassoLogin *login, gchar *response_msg,
		LassoHttpMethod response_http_method);
gint lasso_saml20_login_build_request_msg(LassoLogin *login);
gint lasso_saml20_login_process_request_msg(LassoLogin *login, gchar *request_msg);
gint lasso_saml20_login_build_response_msg(LassoLogin *login);
gint lasso_saml20_login_process_response_msg(LassoLogin *login, gchar *response_msg);
gint lasso_saml20_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg);
gint lasso_saml20_login_accept_sso(LassoLogin *login);
gint lasso_saml20_login_process_paos_response_msg(LassoLogin *login, gchar *paos_response_msg);

gint lasso_saml20_login_init_idp_initiated_authn_request(LassoLogin *login,
		const gchar *remote_providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML20_LOGIN_PRIVATE_H__ */
