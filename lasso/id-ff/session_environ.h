/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __LASSO_SESSION_ENVIRON_H__
#define __LASSO_SESSION_ENVIRON_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/environs/provider.h>
#include <lasso/environs/server_environ.h>
#include <lasso/environs/user_environ.h>

#define LASSO_TYPE_SESSION_ENVIRON (lasso_session_environ_get_type())
#define LASSO_SESSION_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SESSION_ENVIRON, LassoSessionEnviron))
#define LASSO_SESSION_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SESSION_ENVIRON, LassoSessionEnvironClass))
#define LASSO_IS_SESSION_ENVIRON(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SESSION_ENVIRON))
#define LASSP_IS_SESSION_ENVIRON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SESSION_ENVIRON))
#define LASSO_SESSION_ENVIRON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SESSION_ENVIRON, LassoSessionEnvironClass)) 

typedef struct _LassoSessionEnviron LassoSessionEnviron;
typedef struct _LassoSessionEnvironClass LassoSessionEnvironClass;

typedef enum {
     lasso_protocol_profile_type_get = 1,
     lasso_protocol_profile_type_redirect,
     lasso_protocol_profile_type_post,
     lasso_protocol_profile_type_soap,
     lasso_protocol_profile_type_artifact,
} lasso_protocol_profile_type;

struct _LassoSessionEnviron {
  LassoEnviron parent;

  /*< public >*/
  LassoServerEnviron *server;
  LassoUserEnviron   *user;

  char *message;

  LassoNode *request;
  LassoNode *response;

  char *local_providerID, *peer_providerID;

  int request_protocol_profile;
  int response_protocol_profile;

  /*< private >*/
};

struct _LassoSessionEnvironClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType                lasso_session_environ_get_type               (void);

LASSO_EXPORT LassoSessionEnviron *lasso_session_environ_new                    (LassoServerEnviron *server,
										LassoUserEnviron *user,
										gchar *local_providerID,
										gchar *peer_providerID);

LASSO_EXPORT char                *lasso_session_environ_build_authnRequest     (LassoSessionEnviron *session,
										const char *responseProtocolProfile,
										gboolean isPassive,
										gboolean forceAuthn,
										const char *nameIDPolicy);

LASSO_EXPORT gboolean             lasso_session_environ_process_assertion      (LassoSessionEnviron *session, char *str);

LASSO_EXPORT gboolean             lasso_session_environ_process_authnRequest   (LassoSessionEnviron *session,
										char *str_request,
										int protocol_profile_type,
										gboolean has_cookie);

LASSO_EXPORT char                *lasso_session_environ_process_authentication (LassoSessionEnviron *session,
										gboolean isAuthenticated,
										const char *authentication_method);

LASSO_EXPORT int                  lasso_session_environ_set_local_providerID   (LassoSessionEnviron *session, char *providerID);

LASSO_EXPORT int                  lasso_session_environ_set_peer_providerID    (LassoSessionEnviron *session, char *providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SESSION_ENVIRON_H__ */
