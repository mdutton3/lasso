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

#ifndef __LASSO_SAML_ADVICE_H__
#define __LASSO_SAML_ADVICE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_SAML_ADVICE (lasso_saml_advice_get_type())
#define LASSO_SAML_ADVICE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_ADVICE, LassoSamlAdvice))
#define LASSO_SAML_ADVICE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_ADVICE, LassoSamlAdviceClass))
#define LASSO_IS_SAML_ADVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_ADVICE))
#define LASSO_IS_SAML_ADVICE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_ADVICE))
#define LASSO_SAML_ADVICE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_ADVICE, LassoSamlAdviceClass))

typedef struct _LassoSamlAdvice LassoSamlAdvice;
typedef struct _LassoSamlAdviceClass LassoSamlAdviceClass;

struct _LassoSamlAdvice {
	LassoNode parent;

	/*< public >*/
	/* <element ref="saml:AssertionIDReference"/> */
	GList *AssertionIDReference; /* of LassoNode */
	/* <element ref="saml:Assertion"/> */
	struct _LassoSamlAssertion *Assertion;
};

struct _LassoSamlAdviceClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml_advice_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml_advice_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_ADVICE_H__ */
