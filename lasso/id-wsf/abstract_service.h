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

#ifndef __LASSO_ABSTRACT_SERVICE_H__
#define __LASSO_ABSTRACT_SERVICE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/disco_resource_offering.h>
#include <lasso/xml/dst_query_item.h>
#include <lasso/id-wsf/wsf_profile.h>

#define LASSO_TYPE_ABSTRACT_SERVICE (lasso_abstract_service_get_type())
#define LASSO_ABSTRACT_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
       LASSO_TYPE_ABSTRACT_SERVICE, LassoAbstractService))
#define LASSO_ABSTRACT_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
       LASSO_TYPE_ABSTRACT_SERVICE, LassoAbstractServiceClass))
#define LASSO_IS_ABSTRACT_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
       LASSO_TYPE_ABSTRACT_SERVICE))
#define LASSO_IS_ABSTRACT_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
       LASSO_TYPE_ABSTRACT_SERVICE))
#define LASSO_ABSTRACT_SERVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
       LASSO_TYPE_ABSTRACT_SERVICE, LassoAbstractServiceClass)) 

typedef struct _LassoAbstractService LassoAbstractService;
typedef struct _LassoAbstractServiceClass LassoAbstractServiceClass;
typedef struct _LassoAbstractServicePrivate LassoAbstractServicePrivate;

struct _LassoAbstractService {
	LassoWsfProfile parent;

	LassoDiscoResourceOffering *ResourceOffering;

	char *ResourceID;
	gboolean is_encrypted;

	GList *Data;
	GList *QueryItem;

	LassoAbstractServicePrivate *private_data;
};

struct _LassoAbstractServiceClass {
	LassoWsfProfileClass parent;
};


LASSO_EXPORT GType lasso_abstract_service_get_type(void);

LASSO_EXPORT LassoAbstractService* lasso_abstract_service_new(LassoServer *server);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ABSTRACT_SERVICE_H__ */
