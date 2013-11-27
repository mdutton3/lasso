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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "interaction_profile_service.h"
#include "../xml/idwsf_strings.h"
#include "wsf_profile.h"
#include "../xml/soap-1.1/soap_detail.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/is_redirect_request.h"
#include "../utils.h"

/**
 * SECTION:interaction_profile_service
 * @short_description: A service to request user interaction from a principal
 * @stability: Unstable
 *
 */


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

	request = lasso_is_interaction_request_new();
	lasso_node_init_from_message((LassoNode*)request, msg);
	LASSO_WSF_PROFILE(service)->request = LASSO_NODE(request);

	return 0;
}

gint
lasso_interaction_profile_service_process_response_msg(LassoInteractionProfileService *service,
		const gchar *msg)
{
	LassoIsInteractionResponse *response;

	response = lasso_is_interaction_response_new();
	lasso_node_init_from_message((LassoNode*)response, msg);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);

	return 0;
}

/**
 * lasso_interaction_profile_service_build_redirect_response_msg:
 * @profile: a #LassoWsfProfile
 * @redirect_url: an #xmlChar string containing an HTTP url for interaction with the user
 *
 * The redirect_url must contain a way for the interaction service to link this interaction with the
 * current request, usually it is the xml:id of the original request.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_wsf_profile_init_interaction_service_redirect(LassoWsfProfile *profile, char *redirect_url)
{
	LassoSoapDetail *detail = NULL;
	LassoSoapFault *fault = NULL;

	lasso_bad_param(WSF_PROFILE, profile);

	detail = lasso_soap_detail_new();
	fault = lasso_soap_fault_new();
	lasso_assign_new_gobject(fault->Detail, detail);
	lasso_assign_string(fault->faultcode, LASSO_SOAP_FAULT_CODE_SERVER);
	lasso_list_add_new_gobject(detail->any, lasso_is_redirect_request_new(redirect_url));

	return lasso_wsf_profile_init_soap_response(profile, &fault->parent);
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
