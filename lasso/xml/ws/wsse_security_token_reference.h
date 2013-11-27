/* $Id: wsse_security_token_reference.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_WSSE_SECURITY_TOKEN_REFERENCE_H__
#define __LASSO_WSSE_SECURITY_TOKEN_REFERENCE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE \
	(lasso_wsse_security_token_reference_get_type())
#define LASSO_WSSE_SECURITY_TOKEN_REFERENCE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE, \
		LassoWsSec1SecurityTokenReference))
#define LASSO_WSSE_SECURITY_TOKEN_REFERENCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE, \
		LassoWsSec1SecurityTokenReferenceClass))
#define LASSO_IS_WSSE_SECURITY_TOKEN_REFERENCE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE))
#define LASSO_IS_WSSE_SECURITY_TOKEN_REFERENCE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE))
#define LASSO_WSSE_SECURITY_TOKEN_REFERENCE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_WSSE_SECURITY_TOKEN_REFERENCE, \
		LassoWsSec1SecurityTokenReferenceClass))


typedef struct _LassoWsSec1SecurityTokenReference LassoWsSec1SecurityTokenReference;
typedef struct _LassoWsSec1SecurityTokenReferenceClass LassoWsSec1SecurityTokenReferenceClass;


struct _LassoWsSec1SecurityTokenReference {
	LassoNode parent;

	/*< public >*/
	/* attributes */
	char *Id;
	char *Usage;
	GHashTable *attributes;
};


struct _LassoWsSec1SecurityTokenReferenceClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsse_security_token_reference_get_type(void);
LASSO_EXPORT LassoWsSec1SecurityTokenReference* lasso_wsse_security_token_reference_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSSE_SECURITY_TOKEN_REFERENCE_H__ */
