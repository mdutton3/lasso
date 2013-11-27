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

#ifndef __LASSO_SAML20_LOGOUT_PRIVATE_H__
#define __LASSO_SAML20_LOGOUT_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/logout.h"

int lasso_saml20_logout_init_request(LassoLogout *logout,
		LassoProvider *remote_provider, LassoHttpMethod http_method);

int lasso_saml20_logout_build_request_msg(LassoLogout *logout);

int lasso_saml20_logout_process_request_msg(LassoLogout *logout, char *request_msg);

int lasso_saml20_logout_validate_request(LassoLogout *logout);

int lasso_saml20_logout_build_response_msg(LassoLogout *logout);

int lasso_saml20_logout_process_response_msg(LassoLogout *logout, const char *response_msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML20_LOGOUT_PRIVATE_H__ */
