/* $Id: ps_add_entity_response.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_PS_ADD_ENTITY_RESPONSE_H__
#define __LASSO_IDWSF2_PS_ADD_ENTITY_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "ps_response_abstract.h"
#include "ps_object.h"

#define LASSO_TYPE_IDWSF2_PS_ADD_ENTITY_RESPONSE (lasso_idwsf2_ps_add_entity_response_get_type())
#define LASSO_IDWSF2_PS_ADD_ENTITY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_PS_ADD_ENTITY_RESPONSE, \
		LassoIdWsf2PsAddEntityResponse))
#define LASSO_IDWSF2_PS_ADD_ENTITY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_PS_ADD_ENTITY_RESPONSE, \
		LassoIdWsf2PsAddEntityResponseClass))
#define LASSO_IS_IDWSF2_PS_ADD_ENTITY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_PS_ADD_ENTITY_RESPONSE))
#define LASSO_IS_IDWSF2_PS_ADD_ENTITY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_PS_ADD_ENTITY_RESPONSE))
#define LASSO_IDWSF2_PS_ADD_ENTITY_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_PS_ADD_ENTITY_RESPONSE, \
		LassoIdWsf2PsAddEntityResponseClass))


typedef struct _LassoIdWsf2PsAddEntityResponse LassoIdWsf2PsAddEntityResponse;
typedef struct _LassoIdWsf2PsAddEntityResponseClass LassoIdWsf2PsAddEntityResponseClass;


struct _LassoIdWsf2PsAddEntityResponse {
	LassoIdWsf2PsResponseAbstract parent;

	/*< public >*/
	/* elements */
	/* XXX */ void *Object;
	/* XXX */ void *SPtoPSRedirectURL;
	/* XXX */ void *QueryString;
};


struct _LassoIdWsf2PsAddEntityResponseClass {
	LassoIdWsf2PsResponseAbstractClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_ps_add_entity_response_get_type(void);
LASSO_EXPORT LassoIdWsf2PsAddEntityResponse* lasso_idwsf2_ps_add_entity_response_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_PS_ADD_ENTITY_RESPONSE_H__ */
