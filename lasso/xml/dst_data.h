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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_DST_DATA_H__
#define __LASSO_DST_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_DST_DATA (lasso_dst_data_get_type())
#define LASSO_DST_DATA(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DST_DATA, LassoDstData))
#define LASSO_DST_DATA_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_DST_DATA, LassoDstDataClass))
#define LASSO_IS_DST_DATA(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DST_DATA))
#define LASSO_IS_DST_DATA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DST_DATA))
#define LASSO_DST_DATA_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
			LASSO_TYPE_DST_DATA, LassoDstDataClass))

typedef struct _LassoDstData LassoDstData;
typedef struct _LassoDstDataClass LassoDstDataClass;

struct _LassoDstData {
	LassoNode parent;

	GList *any; /* of xmlNode* */

	char *id;
	char *itemIDRef;
};

struct _LassoDstDataClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_dst_data_get_type(void);
LASSO_EXPORT LassoDstData* lasso_dst_data_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DST_DATA_H__ */
