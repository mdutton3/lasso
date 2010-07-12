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

#ifndef __LASSO_ECP_H__
#define __LASSO_ECP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"

#include "../id-ff/profile.h"

#define LASSO_TYPE_ECP (lasso_ecp_get_type())
#define LASSO_ECP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_ECP, LassoEcp))
#define LASSO_ECP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_ECP, LassoEcpClass))
#define LASSO_IS_ECP(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_ECP))
#define LASSO_IS_ECP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_ECP))
#define LASSO_ECP_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_ECP, LassoEcpClass))

typedef struct _LassoEcp LassoEcp;
typedef struct _LassoEcpClass LassoEcpClass;
typedef struct _LassoEcpPrivate LassoEcpPrivate;

struct _LassoEcp {
	LassoProfile parent;

	/*< public >*/
	gchar *assertionConsumerURL;

	/*< private >*/
	LassoEcpPrivate *private_data;
};

struct _LassoEcpClass {
	LassoProfileClass parent_class;
};

LASSO_EXPORT GType lasso_ecp_get_type(void);

LASSO_EXPORT LassoEcp* lasso_ecp_new(LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_ecp_process_authn_request_msg(LassoEcp *ecp,
		const char *authn_request_msg);

LASSO_EXPORT lasso_error_t lasso_ecp_process_response_msg(LassoEcp *ecp,
		const char *response_msg);

LASSO_EXPORT void lasso_ecp_destroy(LassoEcp *ecp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ECP_H__ */
