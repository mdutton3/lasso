/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_SERVICE_H__
#define __LASSO_SERVICE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_SERVICE (lasso_service_get_type())
#define LASSO_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SERVICE, LassoService))
#define LASSO_SERVICE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SERVICE, LassoServiceClass))
#define LASSO_IS_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SERVICE))
#define LASSO_IS_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SERVICE))
#define LASSO_SERVICE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SERVICE, LassoServiceClass)) 

typedef struct _LassoService LassoService;
typedef struct _LassoServiceClass LassoServiceClass;
typedef struct _LassoServicePrivate LassoServicePrivate;

struct _LassoService {
	LassoNode parent;

	gchar *type;
	gchar *endpoint;
	gint ServiceDumpVersion;
};

struct _LassoServiceClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_service_get_type(void);

LASSO_EXPORT LassoService* lasso_service_new(const gchar *type,
					     const gchar *endpoint);

LASSO_EXPORT LassoService* lasso_service_new_from_dump(const gchar *dump);

LASSO_EXPORT gchar* lasso_service_dump(LassoService *service);

LASSO_EXPORT void lasso_service_destroy(LassoService *service);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SERVICE_H__ */
