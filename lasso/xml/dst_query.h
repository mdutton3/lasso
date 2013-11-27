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

#ifndef __LASSO_DST_QUERY_H__
#define __LASSO_DST_QUERY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "disco_encrypted_resource_id.h"
#include "disco_resource_id.h"
#include "dst_query_item.h"
#include "xml.h"

#define LASSO_TYPE_DST_QUERY (lasso_dst_query_get_type())
#define LASSO_DST_QUERY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_DST_QUERY, LassoDstQuery))
#define LASSO_DST_QUERY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_DST_QUERY, LassoDstQueryClass))
#define LASSO_IS_DST_QUERY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DST_QUERY))
#define LASSO_IS_DST_QUERY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DST_QUERY))
#define LASSO_DST_QUERY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
			LASSO_TYPE_DST_QUERY, LassoDstQueryClass))

typedef struct _LassoDstQuery LassoDstQuery;
typedef struct _LassoDstQueryClass LassoDstQueryClass;

struct _LassoDstQuery {
	LassoNode parent;

	/*< public >*/
	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;
	GList *QueryItem; /* of LassoNode */
	GList *Extension; /* of xmlNode* */

	char *id;
	char *itemID;

	/*< private >*/
	char *prefixServiceType;
	char *hrefServiceType;
};

struct _LassoDstQueryClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_dst_query_get_type(void);
LASSO_EXPORT LassoDstQuery* lasso_dst_query_new(LassoDstQueryItem *query_item);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DST_QUERY_H__ */
