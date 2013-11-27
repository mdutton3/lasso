/* $Id: disco_endpoint_context.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_DISCO_ENDPOINT_CONTEXT_H__
#define __LASSO_IDWSF2_DISCO_ENDPOINT_CONTEXT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT \
	(lasso_idwsf2_disco_endpoint_context_get_type())
#define LASSO_IDWSF2_DISCO_ENDPOINT_CONTEXT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT, \
		LassoIdWsf2DiscoEndpointContext))
#define LASSO_IDWSF2_DISCO_ENDPOINT_CONTEXT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT, \
		LassoIdWsf2DiscoEndpointContextClass))
#define LASSO_IS_IDWSF2_DISCO_ENDPOINT_CONTEXT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT))
#define LASSO_IS_IDWSF2_DISCO_ENDPOINT_CONTEXT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT))
#define LASSO_IDWSF2_DISCO_ENDPOINT_CONTEXT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_DISCO_ENDPOINT_CONTEXT, \
		LassoIdWsf2DiscoEndpointContextClass))


typedef struct _LassoIdWsf2DiscoEndpointContext LassoIdWsf2DiscoEndpointContext;
typedef struct _LassoIdWsf2DiscoEndpointContextClass LassoIdWsf2DiscoEndpointContextClass;


struct _LassoIdWsf2DiscoEndpointContext {
	LassoNode parent;

	/*< public >*/
	/* elements */
	GList *Address; /* of strings */
	GList *Framework; /* of LassoNode */
	GList *SecurityMechID; /* of strings */
	GList *Action; /* of strings */
};


struct _LassoIdWsf2DiscoEndpointContextClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_endpoint_context_get_type(void);
LASSO_EXPORT LassoIdWsf2DiscoEndpointContext* lasso_idwsf2_disco_endpoint_context_new(void);

LASSO_EXPORT LassoIdWsf2DiscoEndpointContext* lasso_idwsf2_disco_endpoint_context_new_full(
		const gchar *address);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_ENDPOINT_CONTEXT_H__ */
