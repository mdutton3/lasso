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

#ifndef __LASSO_LOGOUT_RESPONSE_H__
#define __LASSO_LOGOUT_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/protocols/logout_request.h>
#include <lasso/xml/lib_logout_response.h>

#define LASSO_TYPE_LOGOUT_RESPONSE (lasso_logout_response_get_type())
#define LASSO_LOGOUT_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGOUT_RESPONSE, LassoLogoutResponse))
#define LASSO_LOGOUT_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LOGOUT_RESPONSE, LassoLogoutResponseClass))
#define LASSO_IS_LOGOUT_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGOUT_RESPONSE))
#define LASSO_IS_LOGOUT_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGOUT_RESPONSE))
#define LASSO_LOGOUT_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LOGOUT_RESPONSE, LassoLogoutResponseClass)) 

typedef struct _LassoLogoutResponse LassoLogoutResponse;
typedef struct _LassoLogoutResponseClass LassoLogoutResponseClass;

struct _LassoLogoutResponse {
  LassoLibLogoutResponse parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoLogoutResponseClass {
  LassoLibLogoutResponseClass parent;
};

LASSO_EXPORT GType      lasso_logout_response_get_type                (void);

LASSO_EXPORT LassoNode* lasso_logout_response_new                     (gchar       *providerID,
								       const gchar *statusCodeValue,
								       LassoNode   *request);

LASSO_EXPORT LassoNode* lasso_logout_response_new_from_export         (gchar                *buffer,
								       lassoNodeExportTypes  export_type);

LASSO_EXPORT LassoNode* lasso_logout_response_new_from_request_export (gchar                *buffer,
								       lassoNodeExportTypes  export_type,
								       gchar                *providerID,
								       gchar                *statusCodeValue);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LOGOUT_RESPONSE_H__ */
