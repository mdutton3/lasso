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

#ifndef __LASSO_IS_REDIRECT_REQUEST_H__
#define __LASSO_IS_REDIRECT_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_IS_REDIRECT_REQUEST (lasso_is_redirect_request_get_type())
#define LASSO_IS_REDIRECT_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IS_REDIRECT_REQUEST, LassoIsRedirectRequest))
#define LASSO_IS_REDIRECT_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IS_REDIRECT_REQUEST, \
				 LassoIsRedirectRequestClass))
#define LASSO_IS_IS_REDIRECT_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IS_REDIRECT_REQUEST))
#define LASSO_IS_IS_REDIRECT_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_IS_REDIRECT_REQUEST))
#define LASSO_IS_REDIRECT_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IS_REDIRECT_REQUEST, \
				    LassoIsRedirectRequestClass))

typedef struct _LassoIsRedirectRequest LassoIsRedirectRequest;
typedef struct _LassoIsRedirectRequestClass LassoIsRedirectRequestClass;

struct _LassoIsRedirectRequest {
	LassoNode parent;

	char *redirectURL;
};

struct _LassoIsRedirectRequestClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_is_redirect_request_get_type(void);

LASSO_EXPORT LassoIsRedirectRequest* lasso_is_redirect_request_new(const char *redirectURL);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IS_REDIRECT_REQUEST_H__ */
