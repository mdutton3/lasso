/* $Id: subsref_modify_item.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SUBSREF_MODIFY_ITEM_H__
#define __LASSO_IDWSF2_SUBSREF_MODIFY_ITEM_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "subsref_app_data.h"

#define LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM (lasso_idwsf2_subsref_modify_item_get_type())
#define LASSO_IDWSF2_SUBSREF_MODIFY_ITEM(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM, \
		LassoIdWsf2SubsRefModifyItem))
#define LASSO_IDWSF2_SUBSREF_MODIFY_ITEM_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM, \
		LassoIdWsf2SubsRefModifyItemClass))
#define LASSO_IS_IDWSF2_SUBSREF_MODIFY_ITEM(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM))
#define LASSO_IS_IDWSF2_SUBSREF_MODIFY_ITEM_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM))
#define LASSO_IDWSF2_SUBSREF_MODIFY_ITEM_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY_ITEM, \
		LassoIdWsf2SubsRefModifyItemClass))


typedef struct _LassoIdWsf2SubsRefModifyItem LassoIdWsf2SubsRefModifyItem;
typedef struct _LassoIdWsf2SubsRefModifyItemClass LassoIdWsf2SubsRefModifyItemClass;


struct _LassoIdWsf2SubsRefModifyItem {
	LassoNode parent;

	/*< public >*/
	/* elements */
	/* XXX */ void *Select;
	/* XXX */ void *NewData;
	/* attributes */
	char *notChangedSince;
	gboolean overrideAllowed;
	char *id;
	char *itemID;
};


struct _LassoIdWsf2SubsRefModifyItemClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_subsref_modify_item_get_type(void);
LASSO_EXPORT LassoIdWsf2SubsRefModifyItem* lasso_idwsf2_subsref_modify_item_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SUBSREF_MODIFY_ITEM_H__ */
