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

#ifndef __LASSO_LOGOUT_REQUEST_H__
#define __LASSO_LOGOUT_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/lib_logout_request.h>

#define LASSO_TYPE_LOGOUT_REQUEST (lasso_logout_request_get_type())
#define LASSO_LOGOUT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGOUT_REQUEST, LassoLogoutRequest))
#define LASSO_LOGOUT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LOGOUT_REQUEST, LassoLogoutRequestClass))
#define LASSO_IS_LOGOUT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGOUT_REQUEST))
#define LASSO_IS_LOGOUT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGOUT_REQUEST))
#define LASSO_LOGOUT_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LOGOUT_REQUEST, LassoLogoutRequestClass)) 

typedef struct _LassoLogoutRequest LassoLogoutRequest;
typedef struct _LassoLogoutRequestClass LassoLogoutRequestClass;

struct _LassoLogoutRequest {
  LassoLibLogoutRequest parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoLogoutRequestClass {
  LassoLibLogoutRequestClass parent;
};

LASSO_EXPORT GType      lasso_logout_request_get_type       (void);
LASSO_EXPORT LassoNode* lasso_logout_request_new            (const xmlChar *providerID,
							     const xmlChar *nameIdentifier,
							     const xmlChar *nameQualifier,
							     const xmlChar *format);
LASSO_EXPORT LassoNode* lasso_logout_request_new_from_query (const xmlChar *query);
LASSO_EXPORT LassoNode* lasso_logout_request_new_from_soap  (const xmlChar *buffer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LOGOUT_REQUEST_H__ */
