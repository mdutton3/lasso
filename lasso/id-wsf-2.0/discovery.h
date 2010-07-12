/* $Id: discovery.h,v 1.30 2006/02/21 09:51:49 Exp $
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

#ifndef __LASSO_IDWSF2_DISCOVERY_H__
#define __LASSO_IDWSF2_DISCOVERY_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "profile.h"
#include "data_service.h"

#include "../xml/id-wsf-2.0/disco_query.h"
#include "../xml/id-wsf-2.0/disco_query_response.h"
#include "../xml/id-wsf-2.0/disco_svc_metadata.h"

#define LASSO_TYPE_IDWSF2_DISCOVERY (lasso_idwsf2_discovery_get_type())
#define LASSO_IDWSF2_DISCOVERY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IDWSF2_DISCOVERY, LassoIdWsf2Discovery))
#define LASSO_IDWSF2_DISCOVERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IDWSF2_DISCOVERY, LassoIdWsf2DiscoveryClass))
#define LASSO_IS_IDWSF2_DISCOVERY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IDWSF2_DISCOVERY))
#define LASSO_IS_IDWSF2_DISCOVERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_IDWSF2_DISCOVERY))
#define LASSO_IDWSF2_DISCOVERY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IDWSF2_DISCOVERY, LassoIdWsf2DiscoveryClass))

typedef struct _LassoIdWsf2Discovery LassoIdWsf2Discovery;
typedef struct _LassoIdWsf2DiscoveryClass LassoIdWsf2DiscoveryClass;
typedef struct _LassoIdWsf2DiscoveryPrivate LassoIdWsf2DiscoveryPrivate;

struct _LassoIdWsf2Discovery {
	LassoIdWsf2Profile parent;

	/*< private >*/
	LassoIdWsf2DiscoveryPrivate *private_data;
};

struct _LassoIdWsf2DiscoveryClass {
	LassoIdWsf2ProfileClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_discovery_get_type(void);

LASSO_EXPORT LassoIdWsf2Discovery* lasso_idwsf2_discovery_new(LassoServer *server);

/**
 * LassoIdWsf2DiscoveryRequestType:
 * @LASSO_IDWSF2_DISCOVERY_METADATA_REGISTER_REQUEST:
 * @LASSO_IDWSF2_DISCOVERY_METADATA_ASSOCIATION_REQUEST:
 * @LASSO_IDWSF2_DISCOVERY_METADATA_DISSOCIATION_REQUEST:
 * @LASSO_IDWSF2_DISCOVERY_QUERY:
 */
typedef enum {
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_UNKNOWN,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REPLACE,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE,
	LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY,
} LassoIdWsf2DiscoveryRequestType;

/**
 * LassoIdWsf2DiscoveryQueryResultType:
 * @LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_BEST:
 * @LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_ALL:
 * @LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_ONLY_ONE:
 */
typedef enum {
 LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_NONE,
 LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_BEST,
 LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_ALL,
 LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_ONLY_ONE
} LassoIdWsf2DiscoveryQueryResultType;

/* Request initialization */
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_query(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_query(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_register(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_replace(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_delete(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_association_add(
		LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_association_delete(
		LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_init_metadata_association_query(
		LassoIdWsf2Discovery *discovery);

/* Add metadatas to operate on, to make request, but also to make responses. */
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_add_service_metadata(
		LassoIdWsf2Discovery *idwsf2_discovery, LassoIdWsf2DiscoSvcMetadata *service_metadata);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_add_simple_service_metadata(
		LassoIdWsf2Discovery *idwsf2_discovery, const char *abstract,
		const char *provider_id, GList *service_types, GList *options, const char *address,
		GList *security_mechanisms);
LASSO_EXPORT GList* lasso_idwsf2_discovery_get_metadatas(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_add_requested_service(LassoIdWsf2Discovery *discovery,
		GList *service_types, GList *provider_ids, GList *options, GList *security_mechanisms,
		GList *frameworks, GList *actions, LassoIdWsf2DiscoveryQueryResultType result_type,
		const char *req_id);

/* Build the request message */
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_build_request_msg(LassoIdWsf2Discovery *discovery,
		const char *security_mechanism);

/* Handle a request */
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_process_request_msg(LassoIdWsf2Discovery *discovery,
		const char *message);
LASSO_EXPORT LassoIdWsf2DiscoveryRequestType lasso_idwsf2_discovery_get_request_type(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_validate_request(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_fail_request(LassoIdWsf2Discovery *discovery,
		const char *status_code, const char *status_code2);

/* Process the response */
LASSO_EXPORT lasso_error_t lasso_idwsf2_discovery_process_response_msg(LassoIdWsf2Discovery *discovery,
		const char *msg);
LASSO_EXPORT GList* lasso_idwsf2_discovery_get_endpoint_references(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT GList* lasso_idwsf2_discovery_get_svcmdids(LassoIdWsf2Discovery *discovery);
LASSO_EXPORT void lasso_idwsf2_discovery_set_svcmdids(LassoIdWsf2Discovery *discovery, GList *svcmdids);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCOVERY_H__ */

