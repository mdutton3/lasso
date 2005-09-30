/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#ifndef __LASSO_DISCOVERY_H__
#define __LASSO_DISCOVERY_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/disco_insert_entry.h>
#include <lasso/xml/disco_modify.h>
#include <lasso/xml/disco_modify_response.h>
#include <lasso/xml/disco_query.h>
#include <lasso/xml/disco_query_response.h>
#include <lasso/xml/disco_remove_entry.h>
#include <lasso/xml/disco_requested_service_type.h>

#include <lasso/id-wsf/wsf_profile.h>
#include <lasso/id-wsf/data_service.h>

#define LASSO_TYPE_DISCOVERY (lasso_discovery_get_type())
#define LASSO_DISCOVERY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCOVERY, LassoDiscovery))
#define LASSO_DISCOVERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCOVERY, LassoDiscoveryClass))
#define LASSO_IS_DISCOVERY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCOVERY))
#define LASSO_IS_DISCOVERY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCOVERY))
#define LASSO_DISCOVERY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCOVERY, LassoDiscoveryClass)) 

typedef struct _LassoDiscovery LassoDiscovery;
typedef struct _LassoDiscoveryClass LassoDiscoveryClass;
typedef struct _LassoDiscoveryPrivate LassoDiscoveryPrivate;


struct _LassoDiscovery {
	LassoWsfProfile parent;

	/*< public >*/
	LassoDiscoResourceID *resource_id;
	LassoDiscoEncryptedResourceID *encrypted_resource_id;

	/*< private >*/
	LassoDiscoveryPrivate *private_data;
};

struct _LassoDiscoveryClass {
	LassoWsfProfileClass parent;
};

LASSO_EXPORT GType lasso_discovery_get_type(void);

LASSO_EXPORT LassoDiscovery* lasso_discovery_new(LassoServer *server);

LASSO_EXPORT LassoDiscoInsertEntry* lasso_discovery_add_insert_entry(LassoDiscovery *discovery,
	LassoDiscoServiceInstance *serviceInstance, LassoDiscoResourceID *resourceId);

LASSO_EXPORT gint  lasso_discovery_add_remove_entry(LassoDiscovery *discovery,
	const gchar *entryID);

LASSO_EXPORT LassoDiscoRequestedServiceType* lasso_discovery_add_requested_service_type(
	LassoDiscovery *discovery, const gchar *service_type, const gchar *option);

LASSO_EXPORT void lasso_discovery_destroy(LassoDiscovery *discovery);

LASSO_EXPORT gint lasso_discovery_init_insert(LassoDiscovery *discovery,
	LassoDiscoResourceOffering *resourceOffering, const char *security_mech_id);

LASSO_EXPORT gint lasso_discovery_init_remove(LassoDiscovery *discovery, const char *entry_id);

LASSO_EXPORT gint lasso_discovery_build_response_msg(LassoDiscovery *discovery);

LASSO_EXPORT gint lasso_discovery_build_modify_response_msg(LassoDiscovery *discovery);

LASSO_EXPORT gint lasso_discovery_init_modify(LassoDiscovery *discovery,
	LassoDiscoResourceOffering *resourceOffering, LassoDiscoDescription *description);

LASSO_EXPORT gint lasso_discovery_init_query(LassoDiscovery *discovery,
	const gchar *security_mech_id);

LASSO_EXPORT gint lasso_discovery_process_modify_msg(LassoDiscovery *discovery,
	const gchar *message, const gchar *security_mech_id);

LASSO_EXPORT gint lasso_discovery_process_modify_response_msg(LassoDiscovery *discovery,
	const gchar *message);

LASSO_EXPORT gint lasso_discovery_process_query_msg(LassoDiscovery *discovery,
	const gchar *message, const char *security_mech_id);

LASSO_EXPORT gint lasso_discovery_process_query_response_msg(LassoDiscovery *discovery,
	const gchar *message);

LASSO_EXPORT LassoDataService* lasso_discovery_get_service(LassoDiscovery *discovery,
	const char *service_type);

LASSO_EXPORT LassoDataService* lasso_discovery_get_service_with_providerId(
	LassoDiscovery *discovery, const char *providerId);

LASSO_EXPORT GList* lasso_discovery_get_services(LassoDiscovery *discovery);

LASSO_EXPORT LassoDiscoDescription* lasso_discovery_get_description_auto(
		LassoDiscoResourceOffering *offering, const gchar *security_mech);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCOVERY_H__ */
