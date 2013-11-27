/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_LOGOUT_H__
#define __LASSO_LOGOUT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "profile.h"
#include "../xml/lib_logout_request.h"
#include "../xml/lib_logout_response.h"

#define LASSO_TYPE_LOGOUT (lasso_logout_get_type())
#define LASSO_LOGOUT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGOUT, LassoLogout))
#define LASSO_LOGOUT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LOGOUT, LassoLogoutClass))
#define LASSO_IS_LOGOUT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGOUT))
#define LASSO_IS_LOGOUT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGOUT))
#define LASSO_LOGOUT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LOGOUT, LassoLogoutClass))

typedef struct _LassoLogout LassoLogout;
typedef struct _LassoLogoutClass LassoLogoutClass;
typedef struct _LassoLogoutPrivate LassoLogoutPrivate;

struct _LassoLogout {
	LassoProfile parent;

	/*< private >*/
	LassoNode *initial_request;
	LassoNode *initial_response;
	gchar     *initial_remote_providerID;
	gint       providerID_index;
	LassoHttpMethod initial_http_request_method;

	LassoLogoutPrivate *private_data;
};

struct _LassoLogoutClass {
	LassoProfileClass parent;

};

LASSO_EXPORT GType lasso_logout_get_type(void);

LASSO_EXPORT LassoLogout* lasso_logout_new                    (LassoServer       *server);

LASSO_EXPORT LassoLogout* lasso_logout_new_from_dump(LassoServer *server, const gchar *dump);

LASSO_EXPORT lasso_error_t         lasso_logout_build_request_msg      (LassoLogout *logout);

LASSO_EXPORT lasso_error_t         lasso_logout_build_response_msg     (LassoLogout *logout);

LASSO_EXPORT void         lasso_logout_destroy                (LassoLogout *logout);

LASSO_EXPORT gchar*       lasso_logout_dump                   (LassoLogout *logout);

LASSO_EXPORT gchar*       lasso_logout_get_next_providerID    (LassoLogout *logout);

LASSO_EXPORT lasso_error_t         lasso_logout_init_request           (LassoLogout    *logout,
							       gchar          *remote_providerID,
							       LassoHttpMethod request_method);

LASSO_EXPORT lasso_error_t         lasso_logout_process_request_msg    (LassoLogout     *logout,
							       gchar           *request_msg);

LASSO_EXPORT lasso_error_t         lasso_logout_process_response_msg   (LassoLogout     *logout,
							       gchar           *response_msg);

LASSO_EXPORT lasso_error_t         lasso_logout_reset_providerID_index (LassoLogout     *logout);

LASSO_EXPORT lasso_error_t         lasso_logout_validate_request       (LassoLogout *logout);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LOGOUT_H__ */
