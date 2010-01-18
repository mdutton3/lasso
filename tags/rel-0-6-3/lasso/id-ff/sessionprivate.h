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

#ifndef __LASSO_SESSION_PRIVATE_H__
#define __LASSO_SESSION_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/lib_assertion.h>
#include <lasso/xml/samlp_status.h>
#include <lasso/id-ff/session.h>

gint lasso_session_add_assertion(LassoSession *session,
		char *providerID, LassoSamlAssertion *assertion);
gint lasso_session_add_status(LassoSession *session,
		char *providerID, LassoSamlpStatus *authn_response);

LassoSamlAssertion* lasso_session_get_assertion(
		LassoSession *session, gchar *providerID);
LassoSamlpStatus* lasso_session_get_status(
		LassoSession *session, gchar *providerID);

gint lasso_session_remove_status(LassoSession *session, gchar *providerID);
gint lasso_session_remove_assertion(LassoSession *session, gchar *providerID);

void lasso_session_init_provider_ids(LassoSession *session);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SESSION_PRIVATE_H__ */
