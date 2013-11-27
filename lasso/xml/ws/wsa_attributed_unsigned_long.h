/* $Id: wsa_attributed_unsigned_long.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_WSA_ATTRIBUTED_UNSIGNED_LONG_H__
#define __LASSO_WSA_ATTRIBUTED_UNSIGNED_LONG_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_WSA_ATTRIBUTED_UNSIGNED_LONG \
	(lasso_wsa_attributed_unsigned_long_get_type())
#define LASSO_WSA_ATTRIBUTED_UNSIGNED_LONG(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_WSA_ATTRIBUTED_UNSIGNED_LONG, \
		LassoWsAddrAttributedUnsignedLong))
#define LASSO_WSA_ATTRIBUTED_UNSIGNED_LONG_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_WSA_ATTRIBUTED_UNSIGNED_LONG, \
		LassoWsAddrAttributedUnsignedLongClass))
#define LASSO_IS_WSA_ATTRIBUTED_UNSIGNED_LONG(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_WSA_ATTRIBUTED_UNSIGNED_LONG))
#define LASSO_IS_WSA_ATTRIBUTED_UNSIGNED_LONG_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_WSA_ATTRIBUTED_UNSIGNED_LONG))
#define LASSO_WSA_ATTRIBUTED_UNSIGNED_LONG_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_WSA_ATTRIBUTED_UNSIGNED_LONG, \
		LassoWsAddrAttributedUnsignedLongClass))


typedef struct _LassoWsAddrAttributedUnsignedLong LassoWsAddrAttributedUnsignedLong;
typedef struct _LassoWsAddrAttributedUnsignedLongClass LassoWsAddrAttributedUnsignedLongClass;


struct _LassoWsAddrAttributedUnsignedLong {
	LassoNode parent;

	/*< public >*/
	/* elements */
	int content;
	/* attributes */
	GHashTable *attributes;
};


struct _LassoWsAddrAttributedUnsignedLongClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsa_attributed_unsigned_long_get_type(void);
LASSO_EXPORT LassoWsAddrAttributedUnsignedLong* lasso_wsa_attributed_unsigned_long_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSA_ATTRIBUTED_UNSIGNED_LONG_H__ */
