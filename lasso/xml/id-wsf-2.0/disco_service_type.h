/* $Id: disco_service_type.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_DISCO_SERVICE_TYPE_H__
#define __LASSO_IDWSF2_DISCO_SERVICE_TYPE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE (lasso_idwsf2_disco_service_type_get_type())
#define LASSO_IDWSF2_DISCO_SERVICE_TYPE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE, \
		LassoIdWsf2DiscoServiceType))
#define LASSO_IDWSF2_DISCO_SERVICE_TYPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE, \
		LassoIdWsf2DiscoServiceTypeClass))
#define LASSO_IS_IDWSF2_DISCO_SERVICE_TYPE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE))
#define LASSO_IS_IDWSF2_DISCO_SERVICE_TYPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE))
#define LASSO_IDWSF2_DISCO_SERVICE_TYPE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE, \
		LassoIdWsf2DiscoServiceTypeClass))


typedef struct _LassoIdWsf2DiscoServiceType LassoIdWsf2DiscoServiceType;
typedef struct _LassoIdWsf2DiscoServiceTypeClass LassoIdWsf2DiscoServiceTypeClass;


struct _LassoIdWsf2DiscoServiceType {
	LassoNode parent;

	/*< public >*/
	/* elements */
	char *content;
};


struct _LassoIdWsf2DiscoServiceTypeClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_disco_service_type_get_type(void);
LASSO_EXPORT LassoIdWsf2DiscoServiceType* lasso_idwsf2_disco_service_type_new(void);

LASSO_EXPORT LassoIdWsf2DiscoServiceType*
	lasso_idwsf2_disco_service_type_new_with_string(const char *content);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_DISCO_SERVICE_TYPE_H__ */
