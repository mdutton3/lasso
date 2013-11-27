/* $Id: ps_query_objects_request.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_PS_QUERY_OBJECTS_REQUEST_H__
#define __LASSO_IDWSF2_PS_QUERY_OBJECTS_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "subs_subscription.h"
#include "ps_request_abstract.h"

#define LASSO_TYPE_IDWSF2_PS_QUERY_OBJECTS_REQUEST \
	(lasso_idwsf2_ps_query_objects_request_get_type())
#define LASSO_IDWSF2_PS_QUERY_OBJECTS_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_PS_QUERY_OBJECTS_REQUEST, \
		LassoIdWsf2PsQueryObjectsRequest))
#define LASSO_IDWSF2_PS_QUERY_OBJECTS_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_PS_QUERY_OBJECTS_REQUEST, \
		LassoIdWsf2PsQueryObjectsRequestClass))
#define LASSO_IS_IDWSF2_PS_QUERY_OBJECTS_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_PS_QUERY_OBJECTS_REQUEST))
#define LASSO_IS_IDWSF2_PS_QUERY_OBJECTS_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_PS_QUERY_OBJECTS_REQUEST))
#define LASSO_IDWSF2_PS_QUERY_OBJECTS_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_PS_QUERY_OBJECTS_REQUEST, \
		LassoIdWsf2PsQueryObjectsRequestClass))


typedef struct _LassoIdWsf2PsQueryObjectsRequest LassoIdWsf2PsQueryObjectsRequest;
typedef struct _LassoIdWsf2PsQueryObjectsRequestClass LassoIdWsf2PsQueryObjectsRequestClass;


struct _LassoIdWsf2PsQueryObjectsRequest {
	LassoIdWsf2PsRequestAbstract parent;

	/*< public >*/
	/* elements */
	char *Filter;
	/* XXX */ void *Subscription;
	/* attributes */
	int Count;
	int Offset;
};

struct _LassoIdWsf2PsQueryObjectsRequestClass {
	LassoIdWsf2PsRequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_ps_query_objects_request_get_type(void);
LASSO_EXPORT LassoIdWsf2PsQueryObjectsRequest* lasso_idwsf2_ps_query_objects_request_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_PS_QUERY_OBJECTS_REQUEST_H__ */
