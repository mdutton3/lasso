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

#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/id-wsf/abstract_service.h>

struct _LassoAbstractServicePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoAbstractServiceClass *parent_class = NULL;

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoAbstractService *service = LASSO_ABSTRACT_SERVICE(object);

	if (service->private_data->dispose_has_run) {
		return;
	}
	service->private_data->dispose_has_run = TRUE;

	debug("LassoAbstractService object 0x%x disposed ...", service);

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(service));
}

static void
finalize(GObject *object)
{
	LassoAbstractService *service = LASSO_ABSTRACT_SERVICE(object);

	debug("LassoAbstractService object 0x%x finalized ...", object);

	g_free(service->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoAbstractService *service)
{
	service->private_data = g_new(LassoAbstractServicePrivate, 1);
	service->private_data->dispose_has_run = FALSE;

}

static void
class_init(LassoAbstractServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_abstract_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoAbstractServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoAbstractService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
				"LassoAbstractService", &this_info, 0);
	}
	return this_type;
}

LassoAbstractService*
lasso_abstract_service_new(LassoServer *server)
{
	LassoAbstractService *service = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	service = g_object_new(LASSO_TYPE_ABSTRACT_SERVICE, NULL);

	return service;
}
