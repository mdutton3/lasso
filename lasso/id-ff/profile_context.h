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

#ifndef __LASSO_PROFILE_CONTEXT_H__
#define __LASSO_PROFILE_CONTEXT_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/environs/server.h>
#include <lasso/environs/user.h>

#define LASSO_TYPE_PROFILE_CONTEXT (lasso_profile_context_get_type())
#define LASSO_PROFILE_CONTEXT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROFILE_CONTEXT, LassoProfileContext))
#define LASSO_PROFILE_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PROFILE_CONTEXT, LassoProfileContextClass))
#define LASSO_IS_PROFILE_CONTEXT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROFILE_CONTEXT))
#define LASSP_IS_PROFILE_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROFILE_CONTEXT))
#define LASSO_PROFILE_CONTEXT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PROFILE_CONTEXT, LassoProfileContextClass)) 

typedef struct _LassoProfileContext LassoProfileContext;
typedef struct _LassoProfileContextClass LassoProfileContextClass;

typedef enum {
  lassoHttpMethodGet = 1,
  lassoHttpMethodPost,
  lassoHttpMethodRedirect,
} lassoHttpMethods;

struct _LassoProfileContext {
  GObject parent;

  /*< public >*/
  LassoServer *server;
  LassoUser   *user;

  LassoNode *request;
  LassoNode *response;

  gint request_method;
  gint response_method;

  gchar *remote_providerID;
  
  gchar *msg_url;
  gchar *msg_body;

  /*< private >*/
};

struct _LassoProfileContextClass {
  GObjectClass parent;
};

LASSO_EXPORT GType                lasso_profile_context_get_type             (void);

LASSO_EXPORT LassoProfileContext* lasso_profile_context_new                  (LassoServer *server,
									      LassoUser   *user);

LASSO_EXPORT gint                 lasso_profile_context_set_remote_providerID(LassoProfileContext *ctx,
									      gchar               *providerID);

LASSO_EXPORT void                 lasso_profile_context_set_response_status  (LassoProfileContext *ctx,
									      const xmlChar       *statusCodeValue);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROFILE_CONTEXT_H__ */
