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

#ifndef __LASSO_SESSION_H__
#define __LASSO_SESSION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"

#define LASSO_TYPE_SESSION (lasso_session_get_type())
#define LASSO_SESSION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SESSION, LassoSession))
#define LASSO_SESSION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SESSION, LassoSessionClass))
#define LASSO_IS_SESSION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SESSION))
#define LASSO_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SESSION))
#define LASSO_SESSION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SESSION, LassoSessionClass))

typedef struct _LassoSession LassoSession;
typedef struct _LassoSessionClass LassoSessionClass;
typedef struct _LassoSessionPrivate LassoSessionPrivate;

/**
 * LassoSession:
 * @assertions:(element-type string LassoNode): a hashtable of #LassoSamlAssertion or #LassoSaml2Assertion, indexed by provider ids,
 * @is_dirty: whether this session object has been modified since its creation.
 *
 * #LassoSession stores the assertions received or emitted during the current session. It stores
 * state for using profiles like #LassoLogin or #LassoLogout.
 */
struct _LassoSession {
	LassoNode parent;

	/* Can actually contain LassoSamlAssertion or LassoSaml2Assertion */
	GHashTable *assertions; /* of LassoNode */
	gboolean is_dirty;

	/*< private >*/
	LassoSessionPrivate *private_data;
};

struct _LassoSessionClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_session_get_type(void);

LASSO_EXPORT LassoSession* lasso_session_new(void);
LASSO_EXPORT LassoSession* lasso_session_new_from_dump(const gchar *dump);
LASSO_EXPORT gchar* lasso_session_dump(LassoSession *session);
LASSO_EXPORT void lasso_session_destroy(LassoSession *session);

LASSO_EXPORT GList* lasso_session_get_assertions(
	LassoSession *session, const char* provider_id);
LASSO_EXPORT gchar* lasso_session_get_provider_index(LassoSession *session, gint index);
LASSO_EXPORT gboolean lasso_session_is_empty(LassoSession *session);
LASSO_EXPORT lasso_error_t lasso_session_remove_assertion(LassoSession *session, const gchar *providerID);
LASSO_EXPORT LassoNode* lasso_session_get_assertion(
		LassoSession *session, const gchar *providerID);
LASSO_EXPORT lasso_error_t lasso_session_add_assertion(LassoSession *session,
		const char *providerID, LassoNode *assertion);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SESSION_H__ */
