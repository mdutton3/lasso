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

#ifndef __LASSO_DISCO_SERVICE_INSTANCE_H__
#define __LASSO_DISCO_SERVICE_INSTANCE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "disco_description.h"

#define LASSO_TYPE_DISCO_SERVICE_INSTANCE (lasso_disco_service_instance_get_type())
#define LASSO_DISCO_SERVICE_INSTANCE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_SERVICE_INSTANCE, \
				    LassoDiscoServiceInstance))
#define LASSO_DISCO_SERVICE_INSTANCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_SERVICE_INSTANCE, \
				 LassoDiscoServiceInstanceClass))
#define LASSO_IS_DISCO_SERVICE_INSTANCE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_SERVICE_INSTANCE))
#define LASSO_IS_DISCO_SERVICE_INSTANCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_SERVICE_INSTANCE))
#define LASSO_DISCO_SERVICE_INSTANCE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_SERVICE_INSTANCE, \
				    LassoDiscoServiceInstanceClass))

typedef struct _LassoDiscoServiceInstance LassoDiscoServiceInstance;
typedef struct _LassoDiscoServiceInstanceClass LassoDiscoServiceInstanceClass;

struct _LassoDiscoServiceInstance {
	LassoNode parent;

	char *ServiceType;
	char *ProviderID;
	GList *Description; /* of LassoNode */
};

struct _LassoDiscoServiceInstanceClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_service_instance_get_type(void);

LASSO_EXPORT LassoDiscoServiceInstance *lasso_disco_service_instance_copy(
	LassoDiscoServiceInstance *serviceInstance);

LASSO_EXPORT LassoDiscoServiceInstance* lasso_disco_service_instance_new(
	     const gchar *serviceType, const gchar *providerID, LassoDiscoDescription *description);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_SERVICE_INSTANCE_H__ */
