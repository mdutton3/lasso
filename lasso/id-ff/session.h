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
#include <lasso/protocols/elements/assertion.h>

#define LASSO_TYPE_SESSION (lasso_session_get_type())
#define LASSO_SESSION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SESSION, LassoSession))
#define LASSO_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SESSION, LassoSessionClass))
#define LASSO_IS_SESSION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SESSION))
#define LASSO_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SESSION))
#define LASSO_SESSION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SESSION, LassoSessionClass)) 

typedef struct _LassoSession LassoSession;
typedef struct _LassoSessionClass LassoSessionClass;
typedef struct _LassoSessionPrivate LassoSessionPrivate;

struct _LassoSession {
  GObject parent;

  /*< public >*/
  GPtrArray  *providerIDs; /* list of the remote provider IDs for assertions hash table */
  GHashTable *assertions;  /* hash for assertions with remote providerID as key */

  gboolean is_dirty;

  /*< private >*/
  LassoSessionPrivate *private;
};

struct _LassoSessionClass {
  GObjectClass parent;
};

LASSO_EXPORT GType          lasso_session_get_type                             (void);

LASSO_EXPORT LassoSession*  lasso_session_new                                  (void);

LASSO_EXPORT LassoSession*  lasso_session_new_from_dump                        (gchar *dump);

LASSO_EXPORT gint           lasso_session_add_assertion                        (LassoSession *session,
										gchar        *remote_providerID,
										LassoNode    *assertion);
  
LASSO_EXPORT LassoSession*  lasso_session_copy                                 (LassoSession *session);

LASSO_EXPORT void           lasso_session_destroy                              (LassoSession *session);

LASSO_EXPORT gchar*         lasso_session_dump                                 (LassoSession *session);

LASSO_EXPORT LassoNode*     lasso_session_get_assertion                        (LassoSession *session,
										gchar        *remote_providerID);

LASSO_EXPORT gchar*         lasso_session_get_authentication_method            (LassoSession *session,
										gchar        *remote_providerID);

LASSO_EXPORT gchar*         lasso_session_get_next_assertion_remote_providerID (LassoSession *session);

LASSO_EXPORT gint           lasso_session_remove_assertion                     (LassoSession *session,
										gchar        *remote_providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SESSION_H__ */
