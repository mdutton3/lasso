/* $Id: server.h 2945 2006-11-19 20:07:46Z dlaniel $
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

#ifndef __LASSO_IDWSF2_SAML2_LOGIN_PRIVATE_H__
#define __LASSO_IDWSF2_SAML2_LOGIN_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/login.h"
#include "../id-ff/provider.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/saml2_name_id.h"
#include "../xml/ws/wsa_endpoint_reference.h"

LASSO_EXPORT lasso_error_t lasso_login_idwsf2_add_discovery_bootstrap_epr(LassoLogin *login, const char *url,
		const char *abstract, GList *security_mechanisms, int tolerance, int duration);
 
LASSO_EXPORT LassoWsAddrEndpointReference *lasso_login_idwsf2_get_discovery_bootstrap_epr(
		LassoLogin *login);

LASSO_EXPORT LassoWsAddrEndpointReference*
	lasso_saml2_assertion_idwsf2_get_discovery_bootstrap_epr(LassoSaml2Assertion *assertion);

LASSO_EXPORT LassoSaml2Assertion* lasso_server_create_assertion_as_idwsf2_security_token(
		LassoServer *server, LassoSaml2NameID *name_id, int tolerance, int duration,
		gboolean cipher, LassoProvider *audience);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SAML2_LOGIN_PRIVATE_H__ */
