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

#ifndef __LASSO_LOGIN_H__
#define __LASSO_LOGIN_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/environs/profile.h>

#include <lasso/protocols/authn_request.h>
#include <lasso/protocols/authn_response.h>
#include <lasso/protocols/request.h>
#include <lasso/protocols/response.h>

#define LASSO_TYPE_LOGIN (lasso_login_get_type())
#define LASSO_LOGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGIN, LassoLogin))
#define LASSO_LOGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LOGIN, LassoLoginClass))
#define LASSO_IS_LOGIN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGIN))
#define LASSO_IS_LOGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGIN))
#define LASSO_LOGIN_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LOGIN, LassoLoginClass)) 

typedef struct _LassoLogin LassoLogin;
typedef struct _LassoLoginClass LassoLoginClass;
typedef struct _LassoLoginPrivate LassoLoginPrivate;

typedef enum {
  lassoLoginProtocolProfileBrwsArt = 1,
  lassoLoginProtocolProfileBrwsPost,
} lassoLoginProtocolProfile;

struct _LassoLogin {
  LassoProfile parent;
  /*< public >*/
  lassoLoginProtocolProfile protocolProfile;

  gchar     *assertionArtifact;
  gchar     *response_dump;

  /*< private >*/
  LassoNode *assertion;
  lassoHttpMethod http_method;
  LassoLoginPrivate *private;
};

struct _LassoLoginClass {
  LassoProfileClass parent;
};

LASSO_EXPORT GType       lasso_login_get_type                    (void);

LASSO_EXPORT LassoLogin* lasso_login_new                         (LassoServer *server);

LASSO_EXPORT LassoLogin* lasso_login_new_from_dump               (LassoServer *server,
								  gchar       *dump);

LASSO_EXPORT gint        lasso_login_accept_sso                  (LassoLogin *login);

LASSO_EXPORT gint        lasso_login_build_artifact_msg          (LassoLogin      *login,
								  gboolean         authentication_result,
								  const gchar     *authenticationMethod,
								  const gchar     *reauthenticateOnOrAfter,
								  lassoHttpMethod  http_method);

LASSO_EXPORT gint        lasso_login_build_authn_request_msg     (LassoLogin  *login,
								  const gchar *remote_providerID);

LASSO_EXPORT gint        lasso_login_build_authn_response_msg    (LassoLogin  *login,
								  gboolean     authentication_result,
								  const gchar *authenticationMethod,
								  const gchar *reauthenticateOnOrAfter);

LASSO_EXPORT gint        lasso_login_build_request_msg           (LassoLogin *login);

LASSO_EXPORT gint        lasso_login_build_response_msg          (LassoLogin *login);

LASSO_EXPORT void        lasso_login_destroy                     (LassoLogin *login);

LASSO_EXPORT gchar*      lasso_login_dump                        (LassoLogin *login);

LASSO_EXPORT LassoAssertion* lasso_login_get_assertion             (LassoLogin *login);

LASSO_EXPORT gint        lasso_login_init_authn_request          (LassoLogin      *login,
								  lassoHttpMethod  http_method);

LASSO_EXPORT gint        lasso_login_init_from_authn_request_msg (LassoLogin      *login,
								  gchar           *authn_request_msg,
								  lassoHttpMethod  authn_request_http_method);

LASSO_EXPORT gint        lasso_login_init_request                (LassoLogin      *login,
								  gchar           *response_msg,
								  lassoHttpMethod  response_http_method);

LASSO_EXPORT gboolean    lasso_login_must_authenticate           (LassoLogin *login);

LASSO_EXPORT gint        lasso_login_process_authn_response_msg  (LassoLogin *login,
								  gchar      *authn_response_msg);

LASSO_EXPORT gint        lasso_login_process_request_msg         (LassoLogin *login,
								  gchar      *request_msg);

LASSO_EXPORT gint        lasso_login_process_response_msg        (LassoLogin  *login,
								  gchar       *response_msg);

LASSO_EXPORT gint        lasso_login_set_assertion              (LassoLogin     *login,
								 LassoAssertion *assertion);

LASSO_EXPORT gint        lasso_login_set_assertion_from_dump    (LassoLogin *login,
								 gchar      *assertion_dump);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LOGIN_H__ */
