/* $Id: idwsf2_data_service.h 2736 2007-05-30 17:59:38Z dlaniel $
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_IDWSF2_DATA_SERVICE_H__
#define __LASSO_IDWSF2_DATA_SERVICE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "profile.h"
#include "../xml/xml.h"
#include "../xml/id-wsf-2.0/dstref_query_item.h"
#include "../xml/id-wsf-2.0/util_status.h"
#include "../xml/id-wsf-2.0/dstref_data.h"
#include "../xml/ws/wsa_endpoint_reference.h"


#define LASSO_TYPE_IDWSF2_DATA_SERVICE (lasso_idwsf2_data_service_get_type())
#define LASSO_IDWSF2_DATA_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	   LASSO_TYPE_IDWSF2_DATA_SERVICE, LassoIdWsf2DataService))
#define LASSO_IDWSF2_DATA_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
	   LASSO_TYPE_IDWSF2_DATA_SERVICE, LassoIdWsf2DataServiceClass))
#define LASSO_IS_IDWSF2_DATA_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
	   LASSO_TYPE_IDWSF2_DATA_SERVICE))
#define LASSO_IS_IDWSF2_DATA_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
	   LASSO_TYPE_IDWSF2_DATA_SERVICE))
#define LASSO_IDWSF2_DATA_SERVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
	   LASSO_TYPE_IDWSF2_DATA_SERVICE, LassoIdWsf2DataServiceClass))

typedef struct _LassoIdWsf2DataService LassoIdWsf2DataService;
typedef struct _LassoIdWsf2DataServiceClass LassoIdWsf2DataServiceClass;
typedef struct _LassoIdWsf2DataServicePrivate LassoIdWsf2DataServicePrivate;

struct _LassoIdWsf2DataService {
	LassoIdWsf2Profile parent;

	/*< private >*/
	LassoIdWsf2DataServicePrivate *private_data;
};

struct _LassoIdWsf2DataServiceClass {
	LassoIdWsf2ProfileClass parent;
};

typedef enum {
	LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_UNKNOWN,
	LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY,
	LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY,
	LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_CREATE,
	LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_DELETE
} LassoIdWsf2DataServiceRequestType;

LASSO_EXPORT GType lasso_idwsf2_data_service_get_type(void);

/* Service initialization */
LASSO_EXPORT LassoIdWsf2DataService* lasso_idwsf2_data_service_new(LassoServer *server);

/* Request initialization */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_init_query(LassoIdWsf2DataService *service);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_init_modify(LassoIdWsf2DataService *service);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_init_create(LassoIdWsf2DataService *service);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_init_delete(LassoIdWsf2DataService *service);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_set_service_type(LassoIdWsf2DataService *service,
		const char *prefix, const char *service_type);
LASSO_EXPORT const char* lasso_idwsf2_data_service_get_service_type(
		LassoIdWsf2DataService *service);
LASSO_EXPORT const char* lasso_idwsf2_data_service_get_service_type_prefix(
		LassoIdWsf2DataService *service);

/* Manipulate request */
LASSO_EXPORT LassoIdWsf2DataServiceRequestType lasso_idwsf2_data_service_get_request_type(
		LassoIdWsf2DataService *service);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_add_query_item(
	LassoIdWsf2DataService *service, const gchar *item_query, const gchar *item_id);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_add_modify_item(LassoIdWsf2DataService *service,
		const gchar *item_query, xmlNode *new_data, gboolean overrideAllowed,
		const gchar *item_id);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_add_namespace(LassoIdWsf2DataService *data_service,
		const char *prefix, const char *href);

/* Produce request */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_build_request_msg(LassoIdWsf2DataService *service,
		const char *security_mech_id);

/* Handle request */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_process_request_msg(LassoIdWsf2DataService *service,
		const char *msg);
LASSO_EXPORT GList *lasso_idwsf2_data_service_get_item_ids(LassoIdWsf2DataService *data_service);
LASSO_EXPORT GList *lasso_idwsf2_data_service_get_items(LassoIdWsf2DataService *data_service);
LASSO_EXPORT LassoNode* lasso_idwsf2_data_service_get_item(LassoIdWsf2DataService *data_service,
		const char *item_id);

/* Reponse initialization */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_validate_request(LassoIdWsf2DataService *service);
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_set_status_code(LassoIdWsf2DataService *service,
		const char *status_code, const char *status_code2);

/* Manipulate response */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_set_query_item_result(
		LassoIdWsf2DataService *data_service, const char *item_id, xmlNode *xml_data,
		gboolean add);

/* Produce response */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_build_response_msg(LassoIdWsf2DataService *service);

/* Handle response */
LASSO_EXPORT lasso_error_t lasso_idwsf2_data_service_process_response_msg(
	LassoIdWsf2DataService *service, const char *msg);
LASSO_EXPORT LassoIdWsf2UtilStatus *lasso_idwsf2_data_service_get_response_status(
		LassoIdWsf2DataService *service);
LASSO_EXPORT LassoIdWsf2DstRefData* lasso_idwsf2_data_service_get_query_item_result(
		LassoIdWsf2DataService *service, const char *item_id);
LASSO_EXPORT char* lasso_idwsf2_data_service_get_query_item_result_content(
		LassoIdWsf2DataService *service, const char *item_id);
LASSO_EXPORT GList* lasso_idwsf2_data_service_get_query_item_results(
		LassoIdWsf2DataService *service);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DATA_SERVICE_H__ */

