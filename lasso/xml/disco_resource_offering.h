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

#ifndef __LASSO_DISCO_RESOURCE_OFFERING_H__
#define __LASSO_DISCO_RESOURCE_OFFERING_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "disco_resource_id.h"
#include "disco_encrypted_resource_id.h"
#include "disco_service_instance.h"
#include "disco_options.h"

#define LASSO_TYPE_DISCO_RESOURCE_OFFERING (lasso_disco_resource_offering_get_type())
#define LASSO_DISCO_RESOURCE_OFFERING(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_RESOURCE_OFFERING, \
				    LassoDiscoResourceOffering))
#define LASSO_DISCO_RESOURCE_OFFERING_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_RESOURCE_OFFERING, \
				 LassoDiscoResourceOfferingClass))
#define LASSO_IS_DISCO_RESOURCE_OFFERING(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_RESOURCE_OFFERING))
#define LASSO_IS_DISCO_RESOURCE_OFFERING_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_RESOURCE_OFFERING))
#define LASSO_DISCO_RESOURCE_OFFERING_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_RESOURCE_OFFERING, \
				    LassoDiscoResourceOfferingClass))

typedef struct _LassoDiscoResourceOffering LassoDiscoResourceOffering;
typedef struct _LassoDiscoResourceOfferingClass LassoDiscoResourceOfferingClass;

struct _LassoDiscoResourceOffering {
	LassoNode parent;

	/* elements */
	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;
	LassoDiscoServiceInstance *ServiceInstance;

	/*
	 * If the Options element is present, but it is empty, it means that the service instance
	 * explicitly advertises that none of the options are available.
	*/
	LassoDiscoOptions *Options;
	gchar *Abstract;

	/* attributes */
	gchar *entryID;
};

struct _LassoDiscoResourceOfferingClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_resource_offering_get_type(void);

LASSO_EXPORT LassoDiscoResourceOffering* lasso_disco_resource_offering_new(
	LassoDiscoServiceInstance *serviceInstance);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_RESOURCE_OFFERING_H__ */
