/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/xml.h>
#include <lasso/xml/lib_assertion.h>
#include <lasso/xml/samlp_status.h>

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

struct _LassoSession {
	LassoNode parent;

	GHashTable *assertions;  /* hash for assertions with remote providerID as key */
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

LASSO_EXPORT gint lasso_session_add_assertion(LassoSession *session,
		char *providerID, LassoSamlAssertion *assertion);

LASSO_EXPORT gchar* lasso_session_dump(LassoSession *session);

LASSO_EXPORT LassoSamlAssertion* lasso_session_get_assertion(
		LassoSession *session, gchar *providerID);

LASSO_EXPORT gchar* lasso_session_get_provider_index(LassoSession *session, gint index);

LASSO_EXPORT gint lasso_session_remove_assertion(LassoSession *session, gchar *providerID);

LASSO_EXPORT void lasso_session_destroy(LassoSession *session);

gint lasso_session_add_status(LassoSession *session,
		char *providerID, LassoSamlpStatus *authn_response);
LassoSamlpStatus* lasso_session_get_status(LassoSession *session, gchar *providerID);
gint lasso_session_remove_status(LassoSession *session, gchar *providerID);

LASSO_EXPORT gboolean lasso_session_is_empty(LassoSession *session);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SESSION_H__ */
