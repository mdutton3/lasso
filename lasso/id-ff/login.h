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

#ifndef __LASSO_LOGIN_H__
#define __LASSO_LOGIN_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/protocols/provider.h>
#include <lasso/environs/profile_context.h>
#include <lasso/environs/server.h>
#include <lasso/environs/user.h>

#define LASSO_TYPE_LOGIN (lasso_login_get_type())
#define LASSO_LOGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGIN, LassoLogin))
#define LASSO_LOGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LOGIN, LassoLoginClass))
#define LASSO_IS_LOGIN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGIN))
#define LASSP_IS_LOGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGIN))
#define LASSO_LOGIN_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LOGIN, LassoLoginClass)) 

typedef struct _LassoLogin LassoLogin;
typedef struct _LassoLoginClass LassoLoginClass;

typedef enum {
  lassoLoginProtocolPorfileBrwsArt = 1,
  lassoLoginProtocolPorfileBrwsPost,
} lassoLoginProtocolProfiles;

struct _LassoLogin {
  LassoProfileContext parent;
  /*< public >*/
  gint   protocolProfile;
  gchar *assertionArtifact;

  gchar *response_dump;

  gchar *msg_relayState;
  /*< private >*/
};

struct _LassoLoginClass {
  LassoProfileContextClass parent;
};

LASSO_EXPORT GType                lasso_login_get_type                    (void);

LASSO_EXPORT LassoProfileContext* lasso_login_new                         (LassoServer *server,
									   LassoUser   *user);

LASSO_EXPORT gint                 lasso_login_build_artifact_msg          (LassoLogin       *login,
									   gint              authentication_result,
									   const gchar      *authenticationMethod,
									   const gchar      *reauthenticateOnOrAfter,
									   lassoHttpMethods  method);

LASSO_EXPORT gint                 lasso_login_build_authn_request_msg     (LassoLogin *login);

LASSO_EXPORT gint                 lasso_login_build_authn_response_msg    (LassoLogin  *login,
									   gint         authentication_result,
									   const gchar *authenticationMethod,
									   const gchar *reauthenticateOnOrAfter);

LASSO_EXPORT gint                 lasso_login_build_request_msg           (LassoLogin *login);

LASSO_EXPORT gchar*               lasso_login_dump                        (LassoLogin *login);

LASSO_EXPORT gint                 lasso_login_init_authn_request          (LassoLogin  *login,
									   const gchar *remote_providerID);

LASSO_EXPORT gint                 lasso_login_init_from_authn_request_msg (LassoLogin       *login,
									   gchar            *authn_request_msg,
									   lassoHttpMethods  authn_request_method);

LASSO_EXPORT gint                 lasso_login_init_request                (LassoLogin       *login,
									   gchar            *response_msg,
									   lassoHttpMethods  response_method,
									   const gchar      *remote_providerID);

LASSO_EXPORT gint                 lasso_login_handle_authn_response_msg   (LassoLogin *login,
									   gchar      *authn_response_msg);

LASSO_EXPORT gint                 lasso_login_handle_request_msg          (LassoLogin *login,
									   gchar      *request_msg);

LASSO_EXPORT gboolean             lasso_login_must_authenticate           (LassoLogin *login);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LOGIN_H__ */
