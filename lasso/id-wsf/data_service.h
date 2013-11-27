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

#ifndef __LASSO_DATA_SERVICE_H__
#define __LASSO_DATA_SERVICE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "wsf_profile.h"
#include "../xml/disco_resource_id.h"
#include "../xml/disco_encrypted_resource_id.h"
#include "../xml/dst_data.h"
#include "../xml/dst_modification.h"
#include "../xml/dst_query_item.h"
#include "../xml/disco_resource_offering.h"
#include "../xml/xml.h"
#include "../xml/saml_assertion.h"

#define LASSO_TYPE_DATA_SERVICE (lasso_data_service_get_type())
#define LASSO_DATA_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	   LASSO_TYPE_DATA_SERVICE, LassoDataService))
#define LASSO_DATA_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
	   LASSO_TYPE_DATA_SERVICE, LassoDataServiceClass))
#define LASSO_IS_DATA_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
	   LASSO_TYPE_DATA_SERVICE))
#define LASSO_IS_DATA_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
	   LASSO_TYPE_DATA_SERVICE))
#define LASSO_DATA_SERVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
	   LASSO_TYPE_DATA_SERVICE, LassoDataServiceClass))

typedef struct _LassoDataService LassoDataService;
typedef struct _LassoDataServiceClass LassoDataServiceClass;
typedef struct _LassoDataServicePrivate LassoDataServicePrivate;

struct _LassoDataService {
	LassoWsfProfile parent;

	/*< private >*/
	LassoDataServicePrivate *private_data;
};

struct _LassoDataServiceClass {
	LassoWsfProfileClass parent;
};


LASSO_EXPORT GType lasso_data_service_get_type(void);

LASSO_EXPORT LassoDataService* lasso_data_service_new(LassoServer *server);

LASSO_EXPORT LassoDataService* lasso_data_service_new_full(LassoServer *server,
		LassoDiscoResourceOffering *offering);

LASSO_EXPORT lasso_error_t lasso_data_service_init_query(LassoDataService *service,
		const char *select, const char *item_id, const char *security_mech_id);

LASSO_EXPORT lasso_error_t lasso_data_service_add_query_item(LassoDataService *service,
		const char *select, const char *item_id);

LASSO_EXPORT lasso_error_t lasso_data_service_process_request_msg(LassoDataService *service,
		const char *message, const char *security_mech_id);

LASSO_EXPORT lasso_error_t lasso_data_service_validate_request(LassoDataService *service);

LASSO_EXPORT lasso_error_t lasso_data_service_build_query_response_msg(LassoDataService *service);

LASSO_EXPORT lasso_error_t lasso_data_service_build_modify_response_msg(LassoDataService *service);

LASSO_EXPORT lasso_error_t lasso_data_service_build_response_msg(LassoDataService *service);

LASSO_EXPORT lasso_error_t lasso_data_service_process_query_response_msg(LassoDataService *service,
		const char *message);

LASSO_EXPORT lasso_error_t lasso_data_service_get_answer(LassoDataService *service,
		xmlNode **output);

LASSO_EXPORT lasso_error_t lasso_data_service_get_answers(LassoDataService *service, GList **output);

LASSO_EXPORT lasso_error_t lasso_data_service_get_answers_by_select(LassoDataService *service,
		const char *select, GList **output);

LASSO_EXPORT lasso_error_t lasso_data_service_get_answers_by_item_id(LassoDataService *service,
		const char *item_id, GList **output);

LASSO_EXPORT  lasso_error_t lasso_data_service_init_modify(LassoDataService *service,
		const char *security_mech_id);

LASSO_EXPORT lasso_error_t lasso_data_service_add_modification(LassoDataService *service,
		const gchar *select, xmlNode *xmlData, gboolean overrideAllowed,
		time_t *notChangedSince, LassoDstModification **output);


LASSO_EXPORT lasso_error_t lasso_data_service_process_modify_response_msg(LassoDataService *service,
		const gchar *soap_msg);

LASSO_EXPORT lasso_error_t lasso_data_service_get_query_item(LassoDataService *service, const char *select,
		const char *item_id, LassoDstQueryItem **output);

LASSO_EXPORT void lasso_data_service_set_resource_data(LassoDataService *service, const xmlNode *resource_data);

LASSO_EXPORT xmlNode *lasso_data_service_get_resource_data(LassoDataService *service);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DATA_SERVICE_H__ */
