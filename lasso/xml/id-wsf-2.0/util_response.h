/* $Id: util_response.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_UTIL_RESPONSE_H__
#define __LASSO_IDWSF2_UTIL_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "util_status.h"

#define LASSO_TYPE_IDWSF2_UTIL_RESPONSE (lasso_idwsf2_util_response_get_type())
#define LASSO_IDWSF2_UTIL_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_UTIL_RESPONSE, \
		LassoIdWsf2UtilResponse))
#define LASSO_IDWSF2_UTIL_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_UTIL_RESPONSE, \
		LassoIdWsf2UtilResponseClass))
#define LASSO_IS_IDWSF2_UTIL_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_UTIL_RESPONSE))
#define LASSO_IS_IDWSF2_UTIL_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_UTIL_RESPONSE))
#define LASSO_IDWSF2_UTIL_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_UTIL_RESPONSE, \
		LassoIdWsf2UtilResponseClass))


typedef struct _LassoIdWsf2UtilResponse LassoIdWsf2UtilResponse;
typedef struct _LassoIdWsf2UtilResponseClass LassoIdWsf2UtilResponseClass;


struct _LassoIdWsf2UtilResponse {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoIdWsf2UtilStatus *Status;
	GList *Extension; /* of LassoIdWsf2Utilextension */
	/* attributes */
	char *itemIDRef;
	GHashTable *attributes;
};


struct _LassoIdWsf2UtilResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_util_response_get_type(void);
LASSO_EXPORT LassoIdWsf2UtilResponse* lasso_idwsf2_util_response_new(void);
LASSO_EXPORT void lasso_idwsf2_util_response_set_status(
		LassoIdWsf2UtilResponse *idwsf2_util_response, const char *status);
LASSO_EXPORT void lasso_idwsf2_util_response_set_status2(
		LassoIdWsf2UtilResponse *idwsf2_util_response, const char *status, const char *status2);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_UTIL_RESPONSE_H__ */
