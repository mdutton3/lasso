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

#ifndef __LASSO_IDWSF2_SESSION_H__
#define __LASSO_IDWSF2_SESSION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/session.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/ws/wsa_endpoint_reference.h"

LASSO_EXPORT lasso_error_t lasso_session_add_endpoint_reference(LassoSession *session,
	LassoWsAddrEndpointReference *epr);

LASSO_EXPORT LassoWsAddrEndpointReference* lasso_session_get_endpoint_reference(
	LassoSession *session, const gchar *service_type);

LASSO_EXPORT LassoSaml2Assertion* lasso_session_get_assertion_identity_token(
	LassoSession *session, const gchar *service_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SESSION_H__ */

