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

#ifndef __LASSO_SAMLP_RESPONSE_H__
#define __LASSO_SAMLP_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp_response_abstract.h"
#include "samlp_status.h"
#include "saml_assertion.h"

#define LASSO_TYPE_SAMLP_RESPONSE (lasso_samlp_response_get_type())
#define LASSO_SAMLP_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP_RESPONSE, LassoSamlpResponse))
#define LASSO_SAMLP_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP_RESPONSE, LassoSamlpResponseClass))
#define LASSO_IS_SAMLP_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP_RESPONSE))
#define LASSO_IS_SAMLP_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP_RESPONSE))
#define LASSO_SAMLP_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP_RESPONSE, LassoSamlpResponseClass))

typedef struct _LassoSamlpResponse LassoSamlpResponse;
typedef struct _LassoSamlpResponseClass LassoSamlpResponseClass;

struct _LassoSamlpResponse {
	LassoSamlpResponseAbstract parent;

	/*< public >*/
	/* <element ref="samlp:Status"/> */
	LassoSamlpStatus *Status;
	/* <element ref="saml:Assertion" minOccurs="0" maxOccurs="unbounded"/> */
	GList *Assertion; /* of LassoSamlAssertion */
};

struct _LassoSamlpResponseClass {
	LassoSamlpResponseAbstractClass parent;
};

LASSO_EXPORT GType lasso_samlp_response_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp_response_new(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP_RESPONSE_H__ */
