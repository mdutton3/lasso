/* $Id: subsref_modify.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SUBSREF_MODIFY_H__
#define __LASSO_IDWSF2_SUBSREF_MODIFY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "dst_request.h"

#define LASSO_TYPE_IDWSF2_SUBSREF_MODIFY (lasso_idwsf2_subsref_modify_get_type())
#define LASSO_IDWSF2_SUBSREF_MODIFY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY, \
		LassoIdWsf2SubsRefModify))
#define LASSO_IDWSF2_SUBSREF_MODIFY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY, \
		LassoIdWsf2SubsRefModifyClass))
#define LASSO_IS_IDWSF2_SUBSREF_MODIFY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY))
#define LASSO_IS_IDWSF2_SUBSREF_MODIFY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY))
#define LASSO_IDWSF2_SUBSREF_MODIFY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SUBSREF_MODIFY, \
		LassoIdWsf2SubsRefModifyClass))


typedef struct _LassoIdWsf2SubsRefModify LassoIdWsf2SubsRefModify;
typedef struct _LassoIdWsf2SubsRefModifyClass LassoIdWsf2SubsRefModifyClass;


struct _LassoIdWsf2SubsRefModify {
	LassoIdWsf2DstRequest parent;

	/*< public >*/
	/* elements */
	GList *Subscription; /* of LassoNode */
	GList *ModifyItem; /* of LassoNode */
	GList *ResultQuery; /* of LassoNode */
};


struct _LassoIdWsf2SubsRefModifyClass {
	LassoIdWsf2DstRequestClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_subsref_modify_get_type(void);
LASSO_EXPORT LassoIdWsf2SubsRefModify* lasso_idwsf2_subsref_modify_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SUBSREF_MODIFY_H__ */
