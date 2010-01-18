/* $Id: wsse_security_header.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_WSSE_SECURITY_HEADER_H__
#define __LASSO_WSSE_SECURITY_HEADER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_WSSE_SECURITY_HEADER (lasso_wsse_security_header_get_type())
#define LASSO_WSSE_SECURITY_HEADER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_WSSE_SECURITY_HEADER, \
		LassoWsSec1SecurityHeader))
#define LASSO_WSSE_SECURITY_HEADER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_WSSE_SECURITY_HEADER, \
		LassoWsSec1SecurityHeaderClass))
#define LASSO_IS_WSSE_SECURITY_HEADER(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_WSSE_SECURITY_HEADER))
#define LASSO_IS_WSSE_SECURITY_HEADER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_WSSE_SECURITY_HEADER))
#define LASSO_WSSE_SECURITY_HEADER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_WSSE_SECURITY_HEADER, \
		LassoWsSec1SecurityHeaderClass))


typedef struct _LassoWsSec1SecurityHeader LassoWsSec1SecurityHeader;
typedef struct _LassoWsSec1SecurityHeaderClass LassoWsSec1SecurityHeaderClass;


struct _LassoWsSec1SecurityHeader {
	LassoNode parent;

	/*< public >*/
	/* elements */
	GList *any; /* of LassoNode */
	/* attributes */
	GHashTable *attributes;
};


struct _LassoWsSec1SecurityHeaderClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsse_security_header_get_type(void);
LASSO_EXPORT LassoWsSec1SecurityHeader* lasso_wsse_security_header_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSSE_SECURITY_HEADER_H__ */
