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

#ifndef __LASSO_PAOS_REQUEST_H__
#define __LASSO_PAOS_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define LASSO_TYPE_PAOS_REQUEST (lasso_paos_request_get_type())
#define LASSO_PAOS_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PAOS_REQUEST, LassoPaosRequest))
#define LASSO_PAOS_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PAOS_REQUEST, LassoPaosRequestClass))
#define LASSO_IS_PAOS_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PAOS_REQUEST))
#define LASSO_IS_PAOS_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PAOS_REQUEST))
#define LASSO_PAOS_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PAOS_REQUEST, LassoPaosRequestClass))

typedef struct _LassoPaosRequest LassoPaosRequest;
typedef struct _LassoPaosRequestClass LassoPaosRequestClass;

struct _LassoPaosRequest {
	LassoNode parent;

	gchar *responseConsumerURL;
	gchar *messageID;
	gchar *service;
	gboolean mustUnderstand;
	gchar *actor;
};

struct _LassoPaosRequestClass {
	LassoNodeClass parent;
};

LASSO_EXPORT int lasso_paos_request_validate(LassoPaosRequest *node);
LASSO_EXPORT GType lasso_paos_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_paos_request_new(const gchar *responseConsumerURL, const gchar *messageID);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PAOS_REQUEST_H__ */
