/* $Id: subsref_notification.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SUBSREF_NOTIFICATION_H__
#define __LASSO_IDWSF2_SUBSREF_NOTIFICATION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "subs_notification.h"

#define LASSO_TYPE_IDWSF2_SUBSREF_NOTIFICATION \
	(lasso_idwsf2_subsref_notification_get_type())
#define LASSO_IDWSF2_SUBSREF_NOTIFICATION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SUBSREF_NOTIFICATION, \
		LassoIdWsf2SubsRefNotification))
#define LASSO_IDWSF2_SUBSREF_NOTIFICATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SUBSREF_NOTIFICATION, \
		LassoIdWsf2SubsRefNotificationClass))
#define LASSO_IS_IDWSF2_SUBSREF_NOTIFICATION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SUBSREF_NOTIFICATION))
#define LASSO_IS_IDWSF2_SUBSREF_NOTIFICATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SUBSREF_NOTIFICATION))
#define LASSO_IDWSF2_SUBSREF_NOTIFICATION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SUBSREF_NOTIFICATION, \
		LassoIdWsf2SubsRefNotificationClass))


typedef struct _LassoIdWsf2SubsRefNotification LassoIdWsf2SubsRefNotification;
typedef struct _LassoIdWsf2SubsRefNotificationClass LassoIdWsf2SubsRefNotificationClass;


struct _LassoIdWsf2SubsRefNotification {
	LassoIdWsf2SubsNotification parent;

	/*< public >*/
	/* elements */
	GList *ItemData; /* of LassoNode */
};


struct _LassoIdWsf2SubsRefNotificationClass {
	LassoIdWsf2SubsNotificationClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_subsref_notification_get_type(void);
LASSO_EXPORT LassoIdWsf2SubsRefNotification* lasso_idwsf2_subsref_notification_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SUBSREF_NOTIFICATION_H__ */
