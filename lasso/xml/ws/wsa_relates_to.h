/* $Id: wsa_relates_to.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_WSA_RELATES_TO_H__
#define __LASSO_WSA_RELATES_TO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_WSA_RELATES_TO (lasso_wsa_relates_to_get_type())
#define LASSO_WSA_RELATES_TO(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_WSA_RELATES_TO, \
		LassoWsAddrRelatesTo))
#define LASSO_WSA_RELATES_TO_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_WSA_RELATES_TO, \
		LassoWsAddrRelatesToClass))
#define LASSO_IS_WSA_RELATES_TO(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_WSA_RELATES_TO))
#define LASSO_IS_WSA_RELATES_TO_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_WSA_RELATES_TO))
#define LASSO_WSA_RELATES_TO_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_WSA_RELATES_TO, \
		LassoWsAddrRelatesToClass))


typedef struct _LassoWsAddrRelatesTo LassoWsAddrRelatesTo;
typedef struct _LassoWsAddrRelatesToClass LassoWsAddrRelatesToClass;


struct _LassoWsAddrRelatesTo {
	LassoNode parent;

	/*< public >*/
	/* elements */
	char *content;
	/* attributes */
	char *RelationshipType;
	GHashTable *attributes;
};


struct _LassoWsAddrRelatesToClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsa_relates_to_get_type(void);
LASSO_EXPORT LassoWsAddrRelatesTo* lasso_wsa_relates_to_new(void);

LASSO_EXPORT LassoWsAddrRelatesTo* lasso_wsa_relates_to_new_with_string(char *content);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSA_RELATES_TO_H__ */
