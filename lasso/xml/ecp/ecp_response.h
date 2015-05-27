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

#ifndef __LASSO_ECP_RESPONSE_H__
#define __LASSO_ECP_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_ECP_RESPONSE (lasso_ecp_response_get_type())
#define LASSO_ECP_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_ECP_RESPONSE, LassoEcpResponse))
#define LASSO_ECP_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_ECP_RESPONSE, LassoEcpResponseClass))
#define LASSO_IS_ECP_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_ECP_RESPONSE))
#define LASSO_IS_ECP_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_ECP_RESPONSE))
#define LASSO_ECP_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_ECP_RESPONSE, LassoEcpResponseClass))

typedef struct _LassoEcpResponse LassoEcpResponse;
typedef struct _LassoEcpResponseClass LassoEcpResponseClass;

struct _LassoEcpResponse {
	LassoNode parent;

	gboolean mustUnderstand;
	gchar *actor;
	gchar *AssertionConsumerServiceURL;
};

struct _LassoEcpResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT int lasso_ecp_response_validate(LassoEcpResponse *response);
LASSO_EXPORT GType lasso_ecp_response_get_type(void);
LASSO_EXPORT LassoNode* lasso_ecp_response_new(const gchar *AssertionConsumerServiceURL);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ECP_RESPONSE_H__ */
