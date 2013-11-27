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

#ifndef __LASSO_DISCO_SEND_SINGLE_LOGOUT_H__
#define __LASSO_DISCO_SEND_SINGLE_LOGOUT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_DISCO_SEND_SINGLE_LOGOUT (lasso_disco_send_single_logout_get_type())
#define LASSO_DISCO_SEND_SINGLE_LOGOUT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
	 LASSO_TYPE_DISCO_SEND_SINGLE_LOGOUT, LassoDiscoSendSingleLogout))
#define LASSO_DISCO_SEND_SINGLE_LOGOUT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
	 LASSO_TYPE_DISCO_SEND_SINGLE_LOGOUT, LassoDiscoSendSingleLogoutClass))
#define LASSO_IS_DISCO_SEND_SINGLE_LOGOUT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_SEND_SINGLE_LOGOUT))
#define LASSO_IS_DISCO_SEND_SINGLE_LOGOUT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_DISCO_SEND_SINGLE_LOGOUT))
#define LASSO_DISCO_SEND_SINGLE_LOGOUT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
	 LASSO_TYPE_DISCO_SEND_SINGLE_LOGOUT, LassoDiscoSendSingleLogoutClass))

typedef struct _LassoDiscoSendSingleLogout LassoDiscoSendSingleLogout;
typedef struct _LassoDiscoSendSingleLogoutClass LassoDiscoSendSingleLogoutClass;

struct _LassoDiscoSendSingleLogout {
	LassoNode parent;

	gchar *descriptionIDRefs;
};

struct _LassoDiscoSendSingleLogoutClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_send_single_logout_get_type(void);

LASSO_EXPORT LassoDiscoSendSingleLogout* lasso_disco_send_single_logout_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_SEND_SINGLE_LOGOUT_H__ */
