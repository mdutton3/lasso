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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_INTERACTION_PROFILE_SERVICE_H__
#define __LASSO_INTERACTION_PROFILE_SERVICE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "../xml/is_interaction_request.h"
#include "../xml/is_interaction_response.h"
#include "wsf_profile.h"

#define LASSO_TYPE_INTERACTION_PROFILE_SERVICE (lasso_interaction_profile_service_get_type())
#define LASSO_INTERACTION_PROFILE_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	   LASSO_TYPE_INTERACTION_PROFILE_SERVICE, LassoInteractionProfileService))
#define LASSO_INTERACTION_PROFILE_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
	   LASSO_TYPE_INTERACTION_PROFILE_SERVICE, LassoInteractionProfileServiceClass))
#define LASSO_IS_INTERACTION_PROFILE_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
	   LASSO_TYPE_INTERACTION_PROFILE_SERVICE))
#define LASSO_IS_INTERACTION_PROFILE_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
	   LASSO_TYPE_INTERACTION_PROFILE_SERVICE))
#define LASSO_INTERACTION_PROFILE_SERVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
	   LASSO_TYPE_INTERACTION_PROFILE_SERVICE, LassoInteractionProfileServiceClass))

typedef struct _LassoInteractionProfileService LassoInteractionProfileService;
typedef struct _LassoInteractionProfileServiceClass LassoInteractionProfileServiceClass;
typedef struct _LassoInteractionProfileServicePrivate LassoInteractionProfileServicePrivate;

struct _LassoInteractionProfileService {
	LassoWsfProfile parent;

};

struct _LassoInteractionProfileServiceClass {
	LassoWsfProfileClass parent;
};


LASSO_EXPORT GType lasso_interaction_profile_service_get_type(void);

LASSO_EXPORT LassoInteractionProfileService* lasso_interaction_profile_service_new(
	LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_interaction_profile_service_init_request(
	LassoInteractionProfileService *service);

LASSO_EXPORT lasso_error_t lasso_interaction_profile_service_process_request_msg(
	LassoInteractionProfileService *service,
	const gchar *request_msg);

LASSO_EXPORT lasso_error_t lasso_interaction_profile_service_process_response_msg(
	LassoInteractionProfileService *service,
	const gchar *response_msg);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_init_interaction_service_redirect(
		LassoWsfProfile *profile, char *redirect_url);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_INTERACTION_PROFILE_SERVICE_H__ */
