/* $Id: ps_resolve_identifier_response.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE_H__
#define __LASSO_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "ps_response_abstract.h"

#define LASSO_TYPE_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE \
	(lasso_idwsf2_ps_resolve_identifier_response_get_type())
#define LASSO_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE, \
		LassoIdWsf2PsResolveIdentifierResponse))
#define LASSO_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE, \
		LassoIdWsf2PsResolveIdentifierResponseClass))
#define LASSO_IS_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE))
#define LASSO_IS_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE))
#define LASSO_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE, \
		LassoIdWsf2PsResolveIdentifierResponseClass))


typedef struct _LassoIdWsf2PsResolveIdentifierResponse \
	LassoIdWsf2PsResolveIdentifierResponse;
typedef struct _LassoIdWsf2PsResolveIdentifierResponseClass \
	LassoIdWsf2PsResolveIdentifierResponseClass;


struct _LassoIdWsf2PsResolveIdentifierResponse {
	LassoIdWsf2PsResponseAbstract parent;

	/*< public >*/
	/* elements */
	GList *ResolveOutput; /* of LassoNode */
};

struct _LassoIdWsf2PsResolveIdentifierResponseClass {
	LassoIdWsf2PsResponseAbstractClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_ps_resolve_identifier_response_get_type(void);
LASSO_EXPORT LassoIdWsf2PsResolveIdentifierResponse*
	lasso_idwsf2_ps_resolve_identifier_response_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_PS_RESOLVE_IDENTIFIER_RESPONSE_H__ */
