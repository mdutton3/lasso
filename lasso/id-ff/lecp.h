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

#ifndef __LASSO_LECP_H__
#define __LASSO_LECP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"

#include "../xml/lib_authn_request_envelope.h"
#include "../xml/lib_authn_response_envelope.h"

#include "login.h"

#define LASSO_TYPE_LECP (lasso_lecp_get_type())
#define LASSO_LECP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LECP, LassoLecp))
#define LASSO_LECP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LECP, LassoLecpClass))
#define LASSO_IS_LECP(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LECP))
#define LASSO_IS_LECP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LECP))
#define LASSO_LECP_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LECP, LassoLecpClass))

typedef struct _LassoLecp LassoLecp;
typedef struct _LassoLecpClass LassoLecpClass;

struct _LassoLecp {
	LassoLogin parent;

	/*< public >*/
	LassoLibAuthnRequestEnvelope *authnRequestEnvelope;
	LassoLibAuthnResponseEnvelope *authnResponseEnvelope;
	char *assertionConsumerServiceURL;

	/*< private >*/
	void *private_data;  /* reserved for future use */
};

struct _LassoLecpClass {
	LassoLoginClass parent_class;
};

LASSO_EXPORT GType lasso_lecp_get_type(void);

LASSO_EXPORT LassoLecp* lasso_lecp_new(LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp);

LASSO_EXPORT lasso_error_t lasso_lecp_build_authn_request_msg(LassoLecp *lecp);

LASSO_EXPORT lasso_error_t lasso_lecp_build_authn_response_msg(LassoLecp *lecp);

LASSO_EXPORT lasso_error_t  lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp);

LASSO_EXPORT void lasso_lecp_destroy(LassoLecp *lecp);

LASSO_EXPORT lasso_error_t lasso_lecp_init_authn_request(LassoLecp *lecp,
		const char *remote_providerID);

LASSO_EXPORT lasso_error_t lasso_lecp_process_authn_request_msg(LassoLecp *lecp,
		const char *authn_request_msg);

LASSO_EXPORT lasso_error_t lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp,
		const char *request_msg);

LASSO_EXPORT lasso_error_t lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp,
		const char *response_msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LECP_H__ */
