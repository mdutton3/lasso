/* $Id: dst_result_query_base.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_DST_RESULT_QUERY_BASE_H__
#define __LASSO_IDWSF2_DST_RESULT_QUERY_BASE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE (lasso_idwsf2_dst_result_query_base_get_type())
#define LASSO_IDWSF2_DST_RESULT_QUERY_BASE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE, \
		LassoIdWsf2DstResultQueryBase))
#define LASSO_IDWSF2_DST_RESULT_QUERY_BASE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE, \
		LassoIdWsf2DstResultQueryBaseClass))
#define LASSO_IS_IDWSF2_DST_RESULT_QUERY_BASE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE))
#define LASSO_IS_IDWSF2_DST_RESULT_QUERY_BASE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE))
#define LASSO_IDWSF2_DST_RESULT_QUERY_BASE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_DST_RESULT_QUERY_BASE, \
		LassoIdWsf2DstResultQueryBaseClass))


typedef struct _LassoIdWsf2DstResultQueryBase LassoIdWsf2DstResultQueryBase;
typedef struct _LassoIdWsf2DstResultQueryBaseClass LassoIdWsf2DstResultQueryBaseClass;


struct _LassoIdWsf2DstResultQueryBase {
	LassoNode parent;

	/*< public >*/
	/* elements */
	char *ChangeFormat;
	/* attributes */
	char *itemIDRef;
	gboolean contingency;
	gboolean includeCommonAttributes;
	char *changedSince;
	char *itemID;
	char *objectType;
	char *predefined;
};


struct _LassoIdWsf2DstResultQueryBaseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_dst_result_query_base_get_type(void);
LASSO_EXPORT LassoIdWsf2DstResultQueryBase* lasso_idwsf2_dst_result_query_base_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DST_RESULT_QUERY_BASE_H__ */
