/* $Id$
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

#ifndef __LASSO_DST_QUERY_ITEM_H__
#define __LASSO_DST_QUERY_ITEM_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_DST_QUERY_ITEM (lasso_dst_query_item_get_type())
#define LASSO_DST_QUERY_ITEM(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_DST_QUERY_ITEM, LassoDstQueryItem))
#define LASSO_DST_QUERY_ITEM_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_DST_QUERY_ITEM, LassoDstQueryItemClass))
#define LASSO_IS_DST_QUERY_ITEM(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
			LASSO_TYPE_DST_QUERY_ITEM))
#define LASSO_IS_DST_QUERY_ITEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
			LASSO_TYPE_DST_QUERY_ITEM))
#define LASSO_DST_QUERY_ITEM_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
			LASSO_TYPE_DST_QUERY_ITEM, LassoDstQueryItemClass))

typedef struct _LassoDstQueryItem LassoDstQueryItem;
typedef struct _LassoDstQueryItemClass LassoDstQueryItemClass;

struct _LassoDstQueryItem {
	LassoNode parent;

	char *Select;

	char *id;
	gboolean includeCommonAttributes;
	char *itemID;
	char *changedSince;
};

struct _LassoDstQueryItemClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_dst_query_item_get_type(void);
LASSO_EXPORT LassoDstQueryItem* lasso_dst_query_item_new(const char *select, const char *item_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DST_QUERY_ITEM_H__ */
