/* $Id: sb2_user_interaction_header.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SB2_USER_INTERACTION_HEADER_H__
#define __LASSO_IDWSF2_SB2_USER_INTERACTION_HEADER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER \
	(lasso_idwsf2_sb2_user_interaction_header_get_type())
#define LASSO_IDWSF2_SB2_USER_INTERACTION_HEADER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER, \
		LassoIdWsf2Sb2UserInteractionHeader))
#define LASSO_IDWSF2_SB2_USER_INTERACTION_HEADER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER, \
		LassoIdWsf2Sb2UserInteractionHeaderClass))
#define LASSO_IS_IDWSF2_SB2_USER_INTERACTION_HEADER(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER))
#define LASSO_IS_IDWSF2_SB2_USER_INTERACTION_HEADER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER))
#define LASSO_IDWSF2_SB2_USER_INTERACTION_HEADER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER, \
		LassoIdWsf2Sb2UserInteractionHeaderClass))


typedef struct _LassoIdWsf2Sb2UserInteractionHeader LassoIdWsf2Sb2UserInteractionHeader;
typedef struct _LassoIdWsf2Sb2UserInteractionHeaderClass LassoIdWsf2Sb2UserInteractionHeaderClass;


struct _LassoIdWsf2Sb2UserInteractionHeader {
	LassoNode parent;

	/*< public >*/
	/* elements */
	GList *InteractionService; /* of LassoNode */
	/* attributes */
	char *interact;
	char *language;
	gboolean redirect;
	int maxInteractTime;
	GHashTable *attributes;
};

struct _LassoIdWsf2Sb2UserInteractionHeaderClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_sb2_user_interaction_header_get_type(void);
LASSO_EXPORT LassoIdWsf2Sb2UserInteractionHeader*
	lasso_idwsf2_sb2_user_interaction_header_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SB2_USER_INTERACTION_HEADER_H__ */
