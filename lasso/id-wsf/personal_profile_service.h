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

#ifndef __LASSO_PERSONAL_PROFILE_SERVICE_H__
#define __LASSO_PERSONAL_PROFILE_SERVICE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/id-wsf/abstract_service.h>
#include <lasso/xml/disco_resource_offering.h>
#include <lasso/xml/dst_modification.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>
#include <lasso/xml/dst_query_item.h>

#define LASSO_PP_HREF   "urn:liberty:pp:2003-08"
#define LASSO_PP_PREFIX "pp"

#define LASSO_TYPE_PERSONAL_PROFILE_SERVICE (lasso_personal_profile_service_get_type())
#define LASSO_PERSONAL_PROFILE_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
       LASSO_TYPE_PERSONAL_PROFILE_SERVICE, LassoPersonalProfileService))
#define LASSO_PERSONAL_PROFILE_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
       LASSO_TYPE_PERSONAL_PROFILE_SERVICE, LassoPersonalProfileServiceClass))
#define LASSO_IS_PERSONAL_PROFILE_SERVICE(obj) \
       (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PERSONAL_PROFILE_SERVICE))
#define LASSO_IS_PERSONAL_PROFILE_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
       LASSO_TYPE_PERSONAL_PROFILE_SERVICE))
#define LASSO_PERSONAL_PROFILE_SERVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
       LASSO_TYPE_PERSONAL_PROFILE_SERVICE, LassoPersonalProfileServiceClass)) 

typedef struct _LassoPersonalProfileService LassoPersonalProfileService;
typedef struct _LassoPersonalProfileServiceClass LassoPersonalProfileServiceClass;
typedef struct _LassoPersonalProfileServicePrivate LassoPersonalProfileServicePrivate;

struct _LassoPersonalProfileService {
	LassoAbstractService parent;

};

struct _LassoPersonalProfileServiceClass {
	LassoAbstractServiceClass parent;
};


LASSO_EXPORT GType lasso_personal_profile_service_get_type(void);

LASSO_EXPORT LassoPersonalProfileService* lasso_personal_profile_service_new(LassoServer *server);

LASSO_EXPORT gint lasso_personal_profile_service_add_data(
	LassoPersonalProfileService *pp, LassoNode *requested_data);

LASSO_EXPORT LassoDstModification* lasso_personal_profile_service_add_modification(
	LassoPersonalProfileService *pp, const char *select);

LASSO_EXPORT LassoDstQueryItem* lasso_personal_profile_service_add_query_item(
	LassoPersonalProfileService *pp, const char *select);

LASSO_EXPORT  LassoDstModification* lasso_personal_profile_service_init_modify(
	LassoPersonalProfileService *pp,
	LassoDiscoResourceOffering *ro,
	LassoDiscoDescription *description,
	const char *select);

LASSO_EXPORT LassoDstQueryItem* lasso_personal_profile_service_init_query(
	LassoPersonalProfileService *pp,
	LassoDiscoResourceOffering *ro,
	LassoDiscoDescription *description,
	const char *select);

LASSO_EXPORT gint lasso_personal_profile_service_process_modify_msg(LassoPersonalProfileService *pp,
								    const char *modify_soap_msg);

LASSO_EXPORT gint lasso_personal_profile_service_process_modify_response_msg(
	LassoPersonalProfileService *pp,
	const char *modify_response_soap_msg);

LASSO_EXPORT gint lasso_personal_profile_service_process_query_msg(LassoPersonalProfileService *pp,
								   const char *request_soap_msg);
	
LASSO_EXPORT gint lasso_personal_profile_service_process_query_response_msg(
	LassoPersonalProfileService *pp,
	const char *response_soap_msg);

LASSO_EXPORT gint lasso_personal_profile_service_process_request_msg(
		LassoPersonalProfileService *pp, const char *query_soap_msg);

LASSO_EXPORT gint lasso_personal_profile_service_process_response_msg(
		LassoPersonalProfileService *pp, const char *query_response_soap_msg);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PERSONAL_PROFILE_SERVICE_H__ */
