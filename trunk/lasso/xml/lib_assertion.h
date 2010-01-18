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

#ifndef __LASSO_LIB_ASSERTION_H__
#define __LASSO_LIB_ASSERTION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "saml_assertion.h"

#define LASSO_TYPE_LIB_ASSERTION (lasso_lib_assertion_get_type())
#define LASSO_LIB_ASSERTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_ASSERTION, LassoLibAssertion))
#define LASSO_LIB_ASSERTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_ASSERTION, LassoLibAssertionClass))
#define LASSO_IS_LIB_ASSERTION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_ASSERTION))
#define LASSO_IS_LIB_ASSERTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_ASSERTION))
#define LASSO_LIB_ASSERTION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_ASSERTION, LassoLibAssertionClass))

typedef struct _LassoLibAssertion LassoLibAssertion;
typedef struct _LassoLibAssertionClass LassoLibAssertionClass;

struct _LassoLibAssertion {
	LassoSamlAssertion parent;

	/*< public >*/
	char *InResponseTo;
};

struct _LassoLibAssertionClass {
	LassoSamlAssertionClass parent;
};

LASSO_EXPORT GType lasso_lib_assertion_get_type        (void);

LASSO_EXPORT LassoLibAssertion* lasso_lib_assertion_new(void);
LASSO_EXPORT LassoLibAssertion* lasso_lib_assertion_new_full(
		const char *issuer, const char *requestID, const char *audience,
		const char *notBefore, const char *notOnOrAfter);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_ASSERTION_H__ */
