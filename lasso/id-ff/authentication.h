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

#ifndef __LASSO_AUTHENTIFICATION_H__
#define __LASSO_AUTHENTIFICATION_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/protocols/provider.h>
#include <lasso/environs/profile_context.h>
#include <lasso/environs/server.h>
#include <lasso/environs/user.h>

#define LASSO_TYPE_AUTHENTICATION (lasso_authentication_get_type())
#define LASSO_AUTHENTICATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_AUTHENTICATION, LassoAuthentication))
#define LASSO_AUTHENTICATION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_AUTHENTICATION, LassoAuthenticationClass))
#define LASSO_IS_AUTHENTICATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_AUTHENTICATION))
#define LASSP_IS_AUTHENTICATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_AUTHENTICATION))
#define LASSO_AUTHENTICATION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_AUTHENTICATION, LassoAuthenticationClass)) 

typedef struct _LassoAuthentication LassoAuthentication;
typedef struct _LassoAuthenticationClass LassoAuthenticationClass;

struct _LassoAuthentication {
  LassoProfileContext parent;
  /*< public >*/
  /*< private >*/
  gchar *protocolProfile;
  gint request_method;
  gint response_method;
};

struct _LassoAuthenticationClass {
  LassoProfileContextClass parent;
};

LASSO_EXPORT GType                lasso_authentication_get_type               (void);

LASSO_EXPORT LassoProfileContext* lasso_authentication_new                    (LassoServer *server,
									       LassoUser   *user,
									       gchar       *local_providerID,
									       gchar       *remote_providerID,
									       gchar       *request_msg,
									       gint         request_method,
									       gchar       *response_msg,
									       gint         response_method);

LASSO_EXPORT gchar*               lasso_authentication_build_request_msg      (LassoAuthentication *authn);

LASSO_EXPORT gchar*               lasso_authentication_process_authentication_result (LassoAuthentication *authn,
										      gint                 authentication_result,
										      const char          *authentication_method);

LASSO_EXPORT gchar*               lasso_authentication_build_response_msg            (LassoAuthentication *authn,
										      gint                 authentication_result,
										      const gchar         *authenticationMethod,
										      const gchar         *reauthenticateOnOrAfter,
										      gint                 method);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_AUTHENTICATION_H__ */
