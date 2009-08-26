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

#ifndef __LASSO_IS_PARAMETER_H__
#define __LASSO_IS_PARAMETER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_IS_PARAMETER (lasso_is_parameter_get_type())
#define LASSO_IS_PARAMETER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IS_PARAMETER, LassoIsParameter))
#define LASSO_IS_PARAMETER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IS_PARAMETER, LassoIsParameterClass))
#define LASSO_IS_IS_PARAMETER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IS_PARAMETER))
#define LASSO_IS_IS_PARAMETER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_IS_PARAMETER))
#define LASSO_IS_PARAMETER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IS_PARAMETER, LassoIsParameterClass))

typedef struct _LassoIsParameter LassoIsParameter;
typedef struct _LassoIsParameterClass LassoIsParameterClass;

struct _LassoIsParameter {
	LassoNode parent;

	char *name;
	char *value;
};

struct _LassoIsParameterClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_is_parameter_get_type(void);

LASSO_EXPORT LassoIsParameter* lasso_is_parameter_new();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IS_PARAMETER_H__ */
