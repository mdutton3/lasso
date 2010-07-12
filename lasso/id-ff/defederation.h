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

#ifndef __LASSO_DEFEDERATION_H__
#define __LASSO_DEFEDERATION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "profile.h"
#include "../xml/lib_federation_termination_notification.h"

#define LASSO_TYPE_DEFEDERATION (lasso_defederation_get_type())
#define LASSO_DEFEDERATION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DEFEDERATION, LassoDefederation))
#define LASSO_DEFEDERATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DEFEDERATION, LassoDefederationClass))
#define LASSO_IS_DEFEDERATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DEFEDERATION))
#define LASSO_IS_DEFEDERATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DEFEDERATION))
#define LASSO_DEFEDERATION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DEFEDERATION, LassoDefederationClass))

typedef struct _LassoDefederation LassoDefederation;
typedef struct _LassoDefederationClass LassoDefederationClass;

struct _LassoDefederation {
	LassoProfile parent;
	/*< private >*/
	void *private_data;  /* reserved for future use */
};

struct _LassoDefederationClass {
	LassoProfileClass parent;
};

LASSO_EXPORT GType lasso_defederation_get_type(void);

LASSO_EXPORT LassoDefederation *lasso_defederation_new(LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_defederation_build_notification_msg(LassoDefederation *defederation);

LASSO_EXPORT void lasso_defederation_destroy(LassoDefederation *defederation);

LASSO_EXPORT lasso_error_t lasso_defederation_init_notification(LassoDefederation *defederation,
		gchar *remote_providerID, LassoHttpMethod http_method);

LASSO_EXPORT lasso_error_t lasso_defederation_process_notification_msg(
		LassoDefederation *defederation, gchar *notification_msg);

LASSO_EXPORT lasso_error_t lasso_defederation_validate_notification(LassoDefederation *defederation);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DEFEDERATION_H__ */
