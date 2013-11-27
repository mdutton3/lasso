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

#ifndef __LASSO_PROFILE_PRIVATE_H__
#define __LASSO_PROFILE_PRIVATE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "profile.h"

struct _LassoProfilePrivate
{
	char *artifact;
	char *artifact_message;
	gboolean dispose_has_run;
	LassoProfileSignatureHint signature_hint;
	LassoProfileSignatureVerifyHint signature_verify_hint;
};

void lasso_profile_set_response_status(LassoProfile *profile, const gchar *statusCodeValue);
void lasso_profile_clean_msg_info(LassoProfile *profile);

#define LASSO_PROFILE_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_PROFILE, LassoProfilePrivate))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROFILE_PRIVATE_H__ */
