/* $Id$$
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

#ifndef __LASSO_SA_TRANSFORM_H__
#define __LASSO_SA_TRANSFORM_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_SA_TRANSFORM (lasso_sa_transform_get_type())
#define LASSO_SA_TRANSFORM(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_SA_TRANSFORM, LassoSaTransform))
#define LASSO_SA_TRANSFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_SA_TRANSFORM, LassoSaTransformClass))
#define LASSO_IS_SA_TRANSFORM(obj) \
			(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SA_TRANSFORM))
#define LASSO_IS_SA_TRANSFORM_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_SA_TRANSFORM))
#define LASSO_SA_TRANSFORM_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SA_TRANSFORM, LassoSaTransformClass))


typedef struct _LassoSaTransform LassoSaTransform;
typedef struct _LassoSaTransformClass LassoSaTransformClass;

struct _LassoSaTransform {
	LassoNode parent;

	GList *Parameter; /* of LassoNode */

	char *name;
	char *id;
};

struct _LassoSaTransformClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_sa_transform_get_type(void);

LASSO_EXPORT LassoSaTransform* lasso_sa_transform_new();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SA_TRANSFORM_H__ */
