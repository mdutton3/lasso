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

#include <lasso/id-ff/profile.h>

char* lasso_saml20_profile_generate_artifact(LassoProfile *profile, int part);
void lasso_saml20_profile_set_response_status(LassoProfile *profile, const char *status_code_value);
int lasso_saml20_profile_init_artifact_resolve(LassoProfile *profile,
		const char *msg, LassoHttpMethod method);
int lasso_saml20_profile_process_artifact_resolve(LassoProfile *profile, const char *msg);
int lasso_saml20_profile_build_artifact_response(LassoProfile *profile);
int lasso_saml20_profile_process_artifact_response(LassoProfile *profile, const char *msg);
gint lasso_saml20_profile_set_session_from_dump(LassoProfile *profile);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML20_PROFILE_PRIVATE_H__ */
