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

#include "../xml/private.h"
#include "./personal_profile_service.h"
#include "../xml/idwsf_strings.h"
#include "./data_service.h"
#include "./wsf_profile_private.h"
#include "./discovery.h"
#include "../utils.h"

/**
 * SECTION:personal_profile_service
 * @short_description: a subclass of LassoDataService to access Personal Profile datas
 * @stability: Unstable
 */

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

char*
lasso_personal_profile_service_get_email(LassoPersonalProfileService *service)
{
	xmlNode *xmlnode, *child;
	xmlChar *msgAccount = NULL, *msgProvider = NULL;
	char *email;
	GList *answers = NULL, *answer = NULL;
	gint rc = 0;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, NULL);

	rc = lasso_data_service_get_answers_by_select(LASSO_DATA_SERVICE(service),
			"/pp:PP/pp:MsgContact", &answers);

	lasso_foreach(answer, answers)
	{
		xmlnode = (xmlNode*)answer->data;
		child = xmlnode->children;
		while (child != NULL) {
			if (child->type != XML_ELEMENT_NODE) {
				child = child->next;
				continue;
			}

			if (strcmp((char *)child->name, "MsgAccount") == 0) {
				msgAccount = xmlNodeGetContent(child);
			} else if (strcmp((char *)child->name, "MsgProvider") == 0) {
				msgProvider = xmlNodeGetContent(child);
			}

			if (msgAccount != NULL && msgProvider != NULL) {
				break;
			}

			child = child->next;
		}

		if (msgAccount && msgProvider) {
			email = g_strdup_printf("%s@%s", msgAccount, msgProvider);
			break;
		} else {
			email = NULL;
		}
		lasso_release_xml_string(msgAccount);
		lasso_release_xml_string(msgProvider);
		lasso_release_xml_node(xmlnode);
	}

	lasso_release_xml_string(msgAccount);
	lasso_release_xml_string(msgProvider);
	lasso_release_xml_node(xmlnode);
	return email;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

GType
lasso_personal_profile_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		lasso_discovery_register_constructor_for_service_type(LASSO_PP10_HREF,
			(LassoWsfProfileConstructor)lasso_personal_profile_service_new_full);
		static const GTypeInfo this_info = {
			sizeof(LassoPersonalProfileServiceClass),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			sizeof(LassoPersonalProfileService),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_DATA_SERVICE,
				"LassoPersonalProfileService", &this_info, 0);
	}
	return this_type;
}

LassoPersonalProfileService*
lasso_personal_profile_service_new(LassoServer *server)
{
	LassoPersonalProfileService *service;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	service = g_object_new(LASSO_TYPE_PERSONAL_PROFILE_SERVICE, NULL);
	LASSO_WSF_PROFILE(service)->server = g_object_ref(server);

	return service;
}

LassoPersonalProfileService*
lasso_personal_profile_service_new_full(LassoServer *server, LassoDiscoResourceOffering *offering)
{
	LassoPersonalProfileService *service = lasso_personal_profile_service_new(server);

	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(offering), NULL);

	if (service == NULL) {
		return NULL;
	}

	lasso_wsf_profile_set_resource_offering(&service->parent.parent, offering);

	return service;
}

