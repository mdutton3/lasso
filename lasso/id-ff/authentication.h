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
#include <lasso/environs/profile_context.h>
#include <lasso/environs/provider.h>
#include <lasso/environs/server_context.h>
#include <lasso/environs/user_context.h>

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
};

struct _LassoAuthenticationClass {
  LassoProfileContextClass parent;
};

LASSO_EXPORT GType                lasso_authentication_get_type               (void);

LASSO_EXPORT LassoAuthentication* lasso_authentication_new                    (LassoServerAuthentication *server,
									       LassoUserAuthentication   *user,
									       gchar              *local_providerID,
									       gchar              *peer_providerID);

LASSO_EXPORT gchar*               lasso_authentication_build_request          (LassoAuthentication *authn,
									       const gchar         *responseProtocolProfile,
									       gboolean             isPassive,
									       gboolean             forceAuthn,
									       const gchar         *nameIDPolicy);

LASSO_EXPORT xmlChar*             lasso_authentication_process_artifact       (LassoAuthentication *authn,
									       gchar               *artifact);
  
LASSO_EXPORT gboolean             lasso_authentication_process_response       (LassoAuthentication *authn,
										xmlChar             *response);

LASSO_EXPORT gboolean             lasso_authentication_process_request        (LassoAuthentication *authn,
										gchar               *request,
										gint                 request_method,
										gboolean             is_authenticated);

LASSO_EXPORT gchar*               lasso_authentication_process_authentication_result (LassoAuthentication *authn,
										      gint                 authentication_result,
										      const char          *authentication_method);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_AUTHENTICATION_H__ */
