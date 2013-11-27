/* $Id: sb2_credentials_context.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SB2_CREDENTIALS_CONTEXT_H__
#define __LASSO_IDWSF2_SB2_CREDENTIALS_CONTEXT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "../saml-2.0/samlp2_requested_authn_context.h"

#define LASSO_TYPE_IDWSF2_SB2_CREDENTIALS_CONTEXT (lasso_idwsf2_sb2_credentials_context_get_type())
#define LASSO_IDWSF2_SB2_CREDENTIALS_CONTEXT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SB2_CREDENTIALS_CONTEXT, \
		LassoIdWsf2Sb2CredentialsContext))
#define LASSO_IDWSF2_SB2_CREDENTIALS_CONTEXT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SB2_CREDENTIALS_CONTEXT, \
		LassoIdWsf2Sb2CredentialsContextClass))
#define LASSO_IS_IDWSF2_SB2_CREDENTIALS_CONTEXT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SB2_CREDENTIALS_CONTEXT))
#define LASSO_IS_IDWSF2_SB2_CREDENTIALS_CONTEXT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SB2_CREDENTIALS_CONTEXT))
#define LASSO_IDWSF2_SB2_CREDENTIALS_CONTEXT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SB2_CREDENTIALS_CONTEXT, \
		LassoIdWsf2Sb2CredentialsContextClass))


typedef struct _LassoIdWsf2Sb2CredentialsContext LassoIdWsf2Sb2CredentialsContext;
typedef struct _LassoIdWsf2Sb2CredentialsContextClass LassoIdWsf2Sb2CredentialsContextClass;


struct _LassoIdWsf2Sb2CredentialsContext {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoSamlp2RequestedAuthnContext *RequestedAuthnContext;
	GList *SecurityMechID; /* of strings */
	/* attributes */
	GHashTable *attributes;
};


struct _LassoIdWsf2Sb2CredentialsContextClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_sb2_credentials_context_get_type(void);
LASSO_EXPORT LassoIdWsf2Sb2CredentialsContext* lasso_idwsf2_sb2_credentials_context_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SB2_CREDENTIALS_CONTEXT_H__ */
