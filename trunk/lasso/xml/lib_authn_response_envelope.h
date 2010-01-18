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
#ifndef __LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_H__
#define __LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "lib_authn_response.h"

#define LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE (lasso_lib_authn_response_envelope_get_type())
#define LASSO_LIB_AUTHN_RESPONSE_ENVELOPE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE, \
				    LassoLibAuthnResponseEnvelope))
#define LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE, \
				 LassoLibAuthnResponseEnvelopeClass))
#define LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE))
#define LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE))
#define LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE, \
				    LassoLibAuthnResponseEnvelopeClass))

typedef struct _LassoLibAuthnResponseEnvelope LassoLibAuthnResponseEnvelope;
typedef struct _LassoLibAuthnResponseEnvelopeClass LassoLibAuthnResponseEnvelopeClass;

struct _LassoLibAuthnResponseEnvelope {
	LassoNode parent;

	/*< public >*/
	GList *Extension; /* of xmlNode* */
	LassoLibAuthnResponse *AuthnResponse;
	char *AssertionConsumerServiceURL;
};

struct _LassoLibAuthnResponseEnvelopeClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_lib_authn_response_envelope_get_type (void);
LASSO_EXPORT LassoLibAuthnResponseEnvelope* lasso_lib_authn_response_envelope_new(
		LassoLibAuthnResponse *response,
		char *assertionConsumerServiceURL);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_H__ */
