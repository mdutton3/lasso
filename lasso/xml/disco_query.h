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

#ifndef __LASSO_DISCO_QUERY_H__
#define __LASSO_DISCO_QUERY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "disco_resource_id.h"
#include "disco_encrypted_resource_id.h"
#include "disco_requested_service_type.h"

#define LASSO_TYPE_DISCO_QUERY (lasso_disco_query_get_type())
#define LASSO_DISCO_QUERY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_DISCO_QUERY, LassoDiscoQuery))
#define LASSO_DISCO_QUERY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_DISCO_QUERY, LassoDiscoQueryClass))
#define LASSO_IS_DISCO_QUERY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_QUERY))
#define LASSO_IS_DISCO_QUERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_DISCO_QUERY))
#define LASSO_DISCO_QUERY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_QUERY, LassoDiscoQueryClass))

typedef struct _LassoDiscoQuery LassoDiscoQuery;
typedef struct _LassoDiscoQueryClass LassoDiscoQueryClass;

struct _LassoDiscoQuery {
	LassoNode parent;

	LassoDiscoResourceID *ResourceID;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;
	GList *RequestedServiceType; /* of LassoNode */
	gchar *id;
};

struct _LassoDiscoQueryClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_query_get_type(void);

LASSO_EXPORT LassoDiscoQuery* lasso_disco_query_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_QUERY_H__ */
