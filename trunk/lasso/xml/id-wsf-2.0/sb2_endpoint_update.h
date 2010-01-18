/* $Id: sb2_endpoint_update.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SB2_ENDPOINT_UPDATE_H__
#define __LASSO_IDWSF2_SB2_ENDPOINT_UPDATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "../ws/wsa_endpoint_reference.h"

#define LASSO_TYPE_IDWSF2_SB2_ENDPOINT_UPDATE (lasso_idwsf2_sb2_endpoint_update_get_type())
#define LASSO_IDWSF2_SB2_ENDPOINT_UPDATE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SB2_ENDPOINT_UPDATE, \
		LassoIdWsf2Sb2EndpointUpdate))
#define LASSO_IDWSF2_SB2_ENDPOINT_UPDATE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SB2_ENDPOINT_UPDATE, \
		LassoIdWsf2Sb2EndpointUpdateClass))
#define LASSO_IS_IDWSF2_SB2_ENDPOINT_UPDATE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SB2_ENDPOINT_UPDATE))
#define LASSO_IS_IDWSF2_SB2_ENDPOINT_UPDATE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SB2_ENDPOINT_UPDATE))
#define LASSO_IDWSF2_SB2_ENDPOINT_UPDATE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SB2_ENDPOINT_UPDATE, \
		LassoIdWsf2Sb2EndpointUpdateClass))


typedef struct _LassoIdWsf2Sb2EndpointUpdate LassoIdWsf2Sb2EndpointUpdate;
typedef struct _LassoIdWsf2Sb2EndpointUpdateClass LassoIdWsf2Sb2EndpointUpdateClass;


struct _LassoIdWsf2Sb2EndpointUpdate {
	LassoWsAddrEndpointReference parent;

	/*< public >*/
	/* attributes */
	char *updateType;
};


struct _LassoIdWsf2Sb2EndpointUpdateClass {
	LassoWsAddrEndpointReferenceClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_sb2_endpoint_update_get_type(void);
LASSO_EXPORT LassoIdWsf2Sb2EndpointUpdate* lasso_idwsf2_sb2_endpoint_update_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SB2_ENDPOINT_UPDATE_H__ */
