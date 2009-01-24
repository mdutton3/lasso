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

#include <lasso/id-wsf/interaction_profile_service.h>

struct _LassoInteractionProfileServicePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_interaction_profile_service_init_request(LassoInteractionProfileService *service)
{
	LassoWsfProfile *profile;
	LassoIsInteractionRequest *request;

	profile = LASSO_WSF_PROFILE(service);

	request = lasso_is_interaction_request_new();

	profile->request = LASSO_NODE(request);

	return 0;
}


gint
lasso_interaction_profile_service_process_request_msg(LassoInteractionProfileService *service,
		const gchar *msg)
{
	LassoIsInteractionRequest *request;

	request = lasso_is_interaction_request_new_from_message(msg);
	LASSO_WSF_PROFILE(service)->request = LASSO_NODE(request);

	return 0;
}

gint
lasso_interaction_profile_service_process_response_msg(LassoInteractionProfileService *service,
		const gchar *msg)
{
	LassoIsInteractionResponse *response;

	response = lasso_is_interaction_response_new_from_message(msg);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);

	return 0;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoInteractionProfileServiceClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoInteractionProfileServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

}

GType
lasso_interaction_profile_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoInteractionProfileServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoInteractionProfileService),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
				"LassoInteractionProfileService", &this_info, 0);
	}
	return this_type;
}

LassoInteractionProfileService*
lasso_interaction_profile_service_new(LassoServer *server)
{
	LassoInteractionProfileService *service = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	service = g_object_new(LASSO_TYPE_INTERACTION_PROFILE_SERVICE, NULL);

	return service;
}
