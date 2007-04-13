/* $Id: disco_service_context.h 2428 2005-03-10 08:13:36 $
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

#ifndef __LASSO_IDWSF2_DISCO_SERVICE_CONTEXT_H__
#define __LASSO_IDWSF2_DISCO_SERVICE_CONTEXT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/id-wsf-2.0/disco_endpoint_context.h>
#include <lasso/xml/id-wsf-2.0/disco_options.h>

#define LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT (lasso_idwsf2_disco_service_context_get_type())
#define LASSO_IDWSF2_DISCO_SERVICE_CONTEXT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT, \
				    LassoIdWsf2DiscoServiceContext))
#define LASSO_IDWSF2_DISCO_SERVICE_CONTEXT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT, \
				 LassoIdWsf2DiscoServiceContextClass))
#define LASSO_IS_IDWSF2_DISCO_SERVICE_CONTEXT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT))
#define LASSO_IS_IDWSF2_DISCO_SERVICE_CONTEXT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT))
#define LASSO_IDWSF2_DISCO_SERVICE_CONTEXT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IDWSF2_DISCO_SERVICE_CONTEXT, \
				    LassoIdWsf2DiscoServiceContextClass)) 

typedef struct _LassoIdWsf2DiscoServiceContext LassoIdWsf2DiscoServiceContext;
typedef struct _LassoIdWsf2DiscoServiceContextClass LassoIdWsf2DiscoServiceContextClass;

struct _LassoIdWsf2DiscoServiceContext {
	LassoNode parent;

	/* elements */
	gchar *ServiceType;
	LassoIdWsf2DiscoOptions *Options;
	LassoIdWsf2DiscoEndpointContext *EndpointContext;
};

struct _LassoIdWsf2DiscoServiceContextClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_service_context_get_type(void);

LASSO_EXPORT LassoIdWsf2DiscoServiceContext* lasso_idwsf2_disco_service_context_new(
	gchar *serviceType, LassoIdWsf2DiscoEndpointContext *endpointContext);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_SERVICE_CONTEXT_H__ */
