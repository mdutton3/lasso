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

#ifndef __LASSO_DISCO_RESOURCE_OFFERING_H__
#define __LASSO_DISCO_RESOURCE_OFFERING_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/disco_service_instance.h>
#include <lasso/xml/disco_options.h>

#define LASSO_TYPE_DISCO_RESOURCE_OFFERING (lasso_disco_resource_offering_get_type())
#define LASSO_DISCO_RESOURCE_OFFERING(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_RESOURCE_OFFERING, LassoDiscoResourceOffering))
#define LASSO_DISCO_RESOURCE_OFFERING_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_RESOURCE_OFFERING, LassoDiscoResourceOfferingClass))
#define LASSO_IS_DISCO_RESOURCE_OFFERING(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_RESOURCE_OFFERING))
#define LASSO_IS_DISCO_RESOURCE_OFFERING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_RESOURCE_OFFERING))
#define LASSO_DISCO_RESOURCE_OFFERING_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_RESOURCE_OFFERING, LassoDiscoResourceOfferingClass)) 

typedef struct _LassoDiscoResourceOffering LassoDiscoResourceOffering;
typedef struct _LassoDiscoResourceOfferingClass LassoDiscoResourceOfferingClass;

struct _LassoDiscoResourceOffering {
	LassoNode parent;

	/* elements */
	char *ResourceID;
	char *EncryptedResourceID;
	LassoDiscoServiceInstance *ServiceInstance;
	LassoDiscoOptions *Options;
	char *Abstract;

	/* attributes */
	char *entryID;
};

struct _LassoDiscoResourceOfferingClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_resource_offering_get_type(void);

LASSO_EXPORT LassoDiscoResourceOffering* lasso_disco_resource_offering_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_RESOURCE_OFFERING_H__ */
