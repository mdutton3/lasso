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

#include <lasso/id-wsf-2.0/profile.h>
#include <lasso/id-wsf-2.0/data_service.h>

#include <lasso/xml/id-wsf-2.0/disco_query.h>
#include <lasso/xml/id-wsf-2.0/disco_query_response.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_metadata.h>

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

	/* FIXME : Both should be lists */
	LassoIdWsf2DiscoSvcMetadata *metadata;
	gchar *svcMDID;

	/*< private >*/
	LassoIdWsf2DiscoveryPrivate *private_data;
};

struct _LassoIdWsf2DiscoveryClass {
	LassoIdWsf2ProfileClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_discovery_get_type(void);

LASSO_EXPORT LassoIdWsf2Discovery* lasso_idwsf2_discovery_new(LassoServer *server);

LASSO_EXPORT void lasso_idwsf2_discovery_destroy(LassoIdWsf2Discovery *discovery);

LASSO_EXPORT gchar* lasso_idwsf2_discovery_metadata_register_self(LassoIdWsf2Discovery *discovery,
	const gchar *service_type, const gchar *abstract,
	const gchar *soap_endpoint, const gchar *svcMDID);

LASSO_EXPORT gint lasso_idwsf2_discovery_init_metadata_register(LassoIdWsf2Discovery *discovery,
	const gchar *service_type, const gchar *abstract,
	const gchar *disco_provider_id, const gchar *soap_endpoint);

LASSO_EXPORT gint lasso_idwsf2_discovery_process_metadata_register_msg(
	LassoIdWsf2Discovery *discovery, const gchar *message);

LASSO_EXPORT gint lasso_idwsf2_discovery_process_metadata_register_response_msg(
	LassoIdWsf2Discovery *discovery, const gchar *message);
	
LASSO_EXPORT gint lasso_idwsf2_discovery_init_metadata_association_add(
	LassoIdWsf2Discovery *discovery, const gchar *svcMDID);
	
LASSO_EXPORT gint lasso_idwsf2_discovery_process_metadata_association_add_msg(
	LassoIdWsf2Discovery *discovery, const gchar *message);
	
LASSO_EXPORT gint lasso_idwsf2_discovery_register_metadata(LassoIdWsf2Discovery *discovery);

LASSO_EXPORT gint lasso_idwsf2_discovery_process_metadata_association_add_response_msg(
	LassoIdWsf2Discovery *discovery, const gchar *message);

LASSO_EXPORT gint lasso_idwsf2_discovery_init_query(LassoIdWsf2Discovery *discovery,
	const gchar *security_mech_id);

LASSO_EXPORT gint lasso_idwsf2_discovery_add_requested_service_type(LassoIdWsf2Discovery *discovery,
	const gchar *service_type);
	
LASSO_EXPORT gint lasso_idwsf2_discovery_process_query_msg(LassoIdWsf2Discovery *discovery,
	const gchar *message);

LASSO_EXPORT gint lasso_idwsf2_discovery_build_query_response_eprs(
		LassoIdWsf2Discovery *discovery);

LASSO_EXPORT gint lasso_idwsf2_discovery_process_query_response_msg(
		LassoIdWsf2Discovery *discovery, const gchar *message);

LASSO_EXPORT LassoIdWsf2DataService* lasso_idwsf2_discovery_get_service(
	LassoIdWsf2Discovery *discovery, const gchar *service_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCOVERY_H__ */

