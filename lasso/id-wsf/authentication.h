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

#ifndef __LASSO_AUTHENTICATION_H__
#define __LASSO_AUTHENTICATION_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include <sasl/sasl.h>

#include "wsf_profile.h"
#include "../xml/disco_description.h"

#define LASSO_TYPE_AUTHENTICATION (lasso_authentication_get_type())
#define LASSO_AUTHENTICATION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_AUTHENTICATION, LassoAuthentication))
#define LASSO_AUTHENTICATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_AUTHENTICATION, LassoAuthenticationClass))
#define LASSO_IS_AUTHENTICATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_AUTHENTICATION))
#define LASSO_IS_AUTHENTICATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_AUTHENTICATION))
#define LASSO_AUTHENTICATION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_AUTHENTICATION, LassoAuthenticationClass))

typedef struct _LassoAuthentication LassoAuthentication;
typedef struct _LassoAuthenticationClass LassoAuthenticationClass;
typedef struct _LassoAuthenticationPrivate LassoAuthenticationPrivate;

typedef struct LassoUserAccount LassoUserAccount;

typedef enum {
	LASSO_SASL_MECH_ANONYMOUS = 1,
	LASSO_SASL_MECH_PLAIN,
	LASSO_SASL_MECH_CRAM_MD5,
}LassoSaslMechanisms;

struct LassoUserAccount {
	char *login;
	char *password;
};

struct _LassoAuthentication {
	LassoWsfProfile parent;

	/* The SASL context kept for the life of the connection */
	sasl_conn_t *connection;
	sasl_interact_t **client_interact;

	/*< private >*/
	LassoAuthenticationPrivate *private_data;
};

struct _LassoAuthenticationClass {
	LassoWsfProfileClass parent;
};

LASSO_EXPORT GType lasso_authentication_get_type(void);

LASSO_EXPORT LassoAuthentication* lasso_authentication_new(LassoServer *server);

LASSO_EXPORT void lasso_authentication_destroy(LassoAuthentication *authentication);

LASSO_EXPORT lasso_error_t lasso_authentication_client_start(LassoAuthentication *authentication);

LASSO_EXPORT lasso_error_t lasso_authentication_client_step(LassoAuthentication *authentication);

LASSO_EXPORT char *lasso_authentication_get_mechanism_list(LassoAuthentication *authentication);

LASSO_EXPORT lasso_error_t lasso_authentication_init_request(LassoAuthentication *authentication,
						    LassoDiscoDescription *description,
						    const gchar *mechanisms,
						    LassoUserAccount *account);

LASSO_EXPORT lasso_error_t lasso_authentication_process_request_msg(LassoAuthentication *authentication,
							   const gchar *soap_msg);

LASSO_EXPORT lasso_error_t lasso_authentication_process_response_msg(LassoAuthentication *authentication,
							    const gchar *soap_msg);

LASSO_EXPORT lasso_error_t lasso_authentication_server_start(LassoAuthentication *authentication);

LASSO_EXPORT lasso_error_t lasso_authentication_server_step(LassoAuthentication *authentication);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_AUTHENTICATION_H__ */
