/* $Id: discovery.h,v 1.30 2006/02/21 09:51:49 fpeters Exp $ 
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

#ifndef __LASSO_IDWSF2_DISCOVERY_H__
#define __LASSO_IDWSF2_DISCOVERY_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

//#include <lasso/xml/disco_insert_entry.h>
//#include <lasso/xml/disco_modify.h>
//#include <lasso/xml/disco_modify_response.h>
#include <lasso/xml/id-wsf-2.0/disco_query.h>
#include <lasso/xml/id-wsf-2.0/disco_query_response.h>
//#include <lasso/xml/disco_remove_entry.h>
//#include <lasso/xml/disco_requested_service_type.h>

#include <lasso/id-wsf-2.0/wsf2_profile.h>
//#include <lasso/id-wsf/data_service.h>

#define LASSO_TYPE_IDWSF2_DISCOVERY (lasso_idwsf2_discovery_get_type())
#define LASSO_IDWSF2_DISCOVERY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IDWSF2_DISCOVERY, LassoIdwsf2Discovery))
#define LASSO_IDWSF2_DISCOVERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IDWSF2_DISCOVERY, LassoIdwsf2DiscoveryClass))
#define LASSO_IS_IDWSF2_DISCOVERY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IDWSF2_DISCOVERY))
#define LASSO_IS_IDWSF2_DISCOVERY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_IDWSF2_DISCOVERY))
#define LASSO_IDWSF2_DISCOVERY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IDWSF2_DISCOVERY, LassoIdwsf2DiscoveryClass)) 

typedef struct _LassoIdwsf2Discovery LassoIdwsf2Discovery;
typedef struct _LassoIdwsf2DiscoveryClass LassoIdwsf2DiscoveryClass;
typedef struct _LassoIdwsf2DiscoveryPrivate LassoIdwsf2DiscoveryPrivate;


struct _LassoIdwsf2Discovery {
	LassoWsf2Profile parent;

	/*< public >*/
//	LassoDiscoResourceID *resource_id;
//	LassoDiscoEncryptedResourceID *encrypted_resource_id;

	/*< private >*/
	LassoIdwsf2DiscoveryPrivate *private_data;
};

struct _LassoIdwsf2DiscoveryClass {
	LassoWsf2ProfileClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_discovery_get_type(void);

LASSO_EXPORT LassoIdwsf2Discovery* lasso_idwsf2_discovery_new(LassoServer *server);

//LASSO_EXPORT LassoDiscoInsertEntry* lasso_idwsf2_discovery_add_insert_entry(LassoIdwsf2Discovery *discovery,
//	LassoDiscoServiceInstance *serviceInstance, LassoDiscoResourceID *resourceId);
//
//LASSO_EXPORT gint  lasso_idwsf2_discovery_add_remove_entry(LassoIdwsf2Discovery *discovery,
//	const gchar *entryID);
//
//LASSO_EXPORT LassoDiscoRequestedServiceType* lasso_idwsf2_discovery_add_requested_service_type(
//	LassoIdwsf2Discovery *discovery, const gchar *service_type, const gchar *option);

LASSO_EXPORT void lasso_idwsf2_discovery_destroy(LassoIdwsf2Discovery *discovery);

//LASSO_EXPORT gint lasso_idwsf2_discovery_init_insert(LassoIdwsf2Discovery *discovery,
//	LassoDiscoResourceOffering *new_offering, const char *security_mech_id);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_init_remove(LassoIdwsf2Discovery *discovery, const char *entry_id);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_build_response_msg(LassoIdwsf2Discovery *discovery);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_build_modify_response_msg(LassoIdwsf2Discovery *discovery);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_init_modify(LassoIdwsf2Discovery *discovery,
//	LassoDiscoResourceOffering *resourceOffering, LassoDiscoDescription *description);

LASSO_EXPORT gint lasso_idwsf2_discovery_init_query(LassoIdwsf2Discovery *discovery,
	const gchar *security_mech_id);

LASSO_EXPORT gint lasso_idwsf2_discovery_init_metadata_register(LassoIdwsf2Discovery *discovery,
	gchar *service_type, gchar *abstract, gchar *disco_provider_id);
	
//LASSO_EXPORT gint lasso_idwsf2_discovery_process_modify_msg(LassoIdwsf2Discovery *discovery,
//	const gchar *message, const gchar *security_mech_id);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_process_modify_response_msg(LassoIdwsf2Discovery *discovery,
//	const gchar *message);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_process_query_msg(LassoIdwsf2Discovery *discovery,
//	const gchar *message, const char *security_mech_id);
//
//LASSO_EXPORT gint lasso_idwsf2_discovery_process_query_response_msg(LassoIdwsf2Discovery *discovery,
//	const gchar *message);
//
//LASSO_EXPORT LassoDataService* lasso_idwsf2_discovery_get_service(LassoIdwsf2Discovery *discovery,
//	const char *service_type);
//
//LASSO_EXPORT GList* lasso_idwsf2_discovery_get_services(LassoIdwsf2Discovery *discovery);
//
//LASSO_EXPORT LassoDiscoDescription* lasso_idwsf2_discovery_get_description_auto(
//		LassoDiscoResourceOffering *offering, const gchar *security_mech);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCOVERY_H__ */
