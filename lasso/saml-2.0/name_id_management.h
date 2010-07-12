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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __LASSO_NAME_ID_MANAGEMENT_H__
#define __LASSO_NAME_ID_MANAGEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/profile.h"
#include "../xml/saml-2.0/samlp2_manage_name_id_request.h"
#include "../xml/saml-2.0/samlp2_manage_name_id_response.h"

#define LASSO_TYPE_NAME_ID_MANAGEMENT (lasso_name_id_management_get_type())
#define LASSO_NAME_ID_MANAGEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NAME_ID_MANAGEMENT, LassoNameIdManagement))
#define LASSO_NAME_ID_MANAGEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NAME_ID_MANAGEMENT, \
				 LassoNameIdManagementClass))
#define LASSO_IS_NAME_ID_MANAGEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NAME_ID_MANAGEMENT))
#define LASSO_IS_NAME_ID_MANAGEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NAME_ID_MANAGEMENT))
#define LASSO_NAME_ID_MANAGEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NAME_ID_MANAGEMENT, \
				    LassoNameIdManagementClass))

typedef struct _LassoNameIdManagement LassoNameIdManagement;
typedef struct _LassoNameIdManagementClass LassoNameIdManagementClass;

struct _LassoNameIdManagement {
	LassoProfile parent;
	/*< private >*/
	void *private_data;  /* reserved for future use */
};

struct _LassoNameIdManagementClass {
	LassoProfileClass parent;
};

LASSO_EXPORT GType lasso_name_id_management_get_type(void);

LASSO_EXPORT LassoNameIdManagement *lasso_name_id_management_new(LassoServer *server);
LASSO_EXPORT LassoNameIdManagement *lasso_name_id_management_new_from_dump(
		LassoServer *server, const char *dump);
LASSO_EXPORT char* lasso_name_id_management_dump(LassoNameIdManagement *name_id_management);

LASSO_EXPORT void lasso_name_id_management_destroy(LassoNameIdManagement *name_id_management);

LASSO_EXPORT lasso_error_t lasso_name_id_management_init_request(
		LassoNameIdManagement *name_id_management,
		char *remote_provider_id,
		char *new_name_id,
		LassoHttpMethod http_method);
LASSO_EXPORT lasso_error_t lasso_name_id_management_build_request_msg(
		LassoNameIdManagement *name_id_management);

LASSO_EXPORT lasso_error_t lasso_name_id_management_process_request_msg(
		LassoNameIdManagement *name_id_management,
		gchar *request_msg);
LASSO_EXPORT lasso_error_t lasso_name_id_management_validate_request(
		LassoNameIdManagement *name_id_management);
LASSO_EXPORT lasso_error_t lasso_name_id_management_build_response_msg(
		LassoNameIdManagement *name_id_management);
LASSO_EXPORT lasso_error_t lasso_name_id_management_process_response_msg(
		LassoNameIdManagement *name_id_management,
		gchar *response_msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_NAME_ID_MANAGEMENT_H__ */
