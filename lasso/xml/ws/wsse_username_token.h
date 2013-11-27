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

#ifndef __LASSO_WSSE_USERNAME_TOKEN_H__
#define __LASSO_WSSE_USERNAME_TOKEN_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_WSSE_USERNAME_TOKEN (lasso_wsse_username_token_get_type())
#define LASSO_WSSE_USERNAME_TOKEN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
			LASSO_TYPE_WSSE_USERNAME_TOKEN, LassoWsseUsernameToken))
#define LASSO_WSSE_USERNAME_TOKEN_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
			LASSO_TYPE_WSSE_USERNAME_TOKEN, LassoWsseUsernameTokenClass))
#define LASSO_IS_WSSE_USERNAME_TOKEN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_WSSE_USERNAME_TOKEN))
#define LASSO_IS_WSSE_USERNAME_TOKEN_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass),LASSO_TYPE_WSSE_USERNAME_TOKEN))
#define LASSO_WSSE_USERNAME_TOKEN_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_WSSE_USERNAME_TOKEN, LassoWsseUsernameTokenClass))

typedef struct _LassoWsseUsernameToken LassoWsseUsernameToken;
typedef struct _LassoWsseUsernameTokenClass LassoWsseUsernameTokenClass;

typedef enum {
	LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_UNKNOWN,
	LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_TEXT,
	LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_DIGEST,
	LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_LAST
} LassoWsseUsernameTokenPasswordType;

struct _LassoWsseUsernameToken {
	LassoNode parent;

	char *Id;
	char *Username;
	char *Nonce;
	char *Salt;
	char *Created;
	int Iteration;
	GHashTable *attributes;
};

struct _LassoWsseUsernameTokenClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsse_username_token_get_type(void);

LASSO_EXPORT LassoWsseUsernameToken* lasso_wsse_username_token_new(void);

LASSO_EXPORT void lasso_wsse_username_token_reset_nonce(LassoWsseUsernameToken *wsse_username_token);

LASSO_EXPORT void lasso_wsse_username_token_set_password_kind(LassoWsseUsernameToken *wsse_username_token, LassoWsseUsernameTokenPasswordType password_type);

LASSO_EXPORT lasso_error_t lasso_wsse_username_token_set_password(LassoWsseUsernameToken *wsse_username_token, char *password);

LASSO_EXPORT lasso_error_t lasso_wsse_username_token_check_password(LassoWsseUsernameToken *wsse_username_token, char *password);

LASSO_EXPORT guchar* lasso_wsse_username_token_derive_key(LassoWsseUsernameToken *wsse_username_token, char *password);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSSE_USERNAME_TOKEN_H__ */
