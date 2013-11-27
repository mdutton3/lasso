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

#ifndef __LASSO_SESSION_PRIVATE_H__
#define __LASSO_SESSION_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/lib_assertion.h"
#include "../xml/samlp_status.h"
#include "session.h"
#include "../xml/xml.h"
#include "lasso/lasso_config.h"

struct _LassoSessionPrivate
{
	gboolean dispose_has_run;
	GList *providerIDs;
	GHashTable *status; /* hold temporary response status for sso-art */
	GHashTable *assertions_by_id;
	GHashTable *nid_and_session_indexes;
#ifdef LASSO_WSF_ENABLED
	GHashTable *eprs;
#endif
};

#define LASSO_SESSION_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_SESSION, LassoSessionPrivate))

gint lasso_session_add_status(LassoSession *session,
		const char *providerID, LassoNode *status);
gint lasso_session_add_assertion_with_id(LassoSession *session,
		const char *assertionID, xmlNode *assertion);

xmlNode* lasso_session_get_assertion_by_id(
		LassoSession *session, const gchar *assertionID);
LassoNode* lasso_session_get_status(
		LassoSession *session, const gchar *providerID);

gint lasso_session_remove_status(LassoSession *session, const gchar *providerID);
gint lasso_session_count_assertions(LassoSession *session);
gboolean lasso_session_is_dirty(LassoSession *session);

void lasso_session_init_provider_ids(LassoSession *session);

gboolean lasso_session_has_slo_session(LassoSession *session, const gchar *provider_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SESSION_PRIVATE_H__ */
