/* $Id: sec_transited_provider_path.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SEC_TRANSITED_PROVIDER_PATH_H__
#define __LASSO_IDWSF2_SEC_TRANSITED_PROVIDER_PATH_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH \
	(lasso_idwsf2_sec_transited_provider_path_get_type())
#define LASSO_IDWSF2_SEC_TRANSITED_PROVIDER_PATH(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH, \
		LassoIdWsf2SecTransitedProviderPath))
#define LASSO_IDWSF2_SEC_TRANSITED_PROVIDER_PATH_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH, \
		LassoIdWsf2SecTransitedProviderPathClass))
#define LASSO_IS_IDWSF2_SEC_TRANSITED_PROVIDER_PATH(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH))
#define LASSO_IS_IDWSF2_SEC_TRANSITED_PROVIDER_PATH_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH))
#define LASSO_IDWSF2_SEC_TRANSITED_PROVIDER_PATH_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SEC_TRANSITED_PROVIDER_PATH, \
		LassoIdWsf2SecTransitedProviderPathClass))


typedef struct _LassoIdWsf2SecTransitedProviderPath LassoIdWsf2SecTransitedProviderPath;
typedef struct _LassoIdWsf2SecTransitedProviderPathClass LassoIdWsf2SecTransitedProviderPathClass;


struct _LassoIdWsf2SecTransitedProviderPath {
	LassoNode parent;

	/*< public >*/
	/* elements */
	GList *TransitedProvider; /* of LassoNode */
};

struct _LassoIdWsf2SecTransitedProviderPathClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_sec_transited_provider_path_get_type(void);
LASSO_EXPORT LassoIdWsf2SecTransitedProviderPath*
	lasso_idwsf2_sec_transited_provider_path_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SEC_TRANSITED_PROVIDER_PATH_H__ */
