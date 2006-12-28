/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <lasso/id-wsf/personal_profile_service.h>
#include <lasso/id-wsf/data_service_private.h>


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

char*
lasso_personal_profile_service_get_email(LassoPersonalProfileService *service)
{
	xmlNode *xmlnode, *child;
	xmlChar *msgAccount = NULL, *msgProvider = NULL;
	char *email;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, NULL);

	xmlnode = lasso_data_service_get_answer(LASSO_DATA_SERVICE(service),
			"/pp:PP/pp:MsgContact");

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
	} else {
		email = NULL;
	}
	xmlFree(msgAccount);
	xmlFree(msgProvider);
	xmlFreeNode(xmlnode);

	return email;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoPersonalProfileService *service)
{

}

static void
class_init(LassoPersonalProfileServiceClass *klass)
{

}

GType
lasso_personal_profile_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoPersonalProfileServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoPersonalProfileService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE_SERVICE,
				"LassoPersonalProfileService", &this_info, 0);
	}
	return this_type;
}

LassoPersonalProfileService*
lasso_personal_profile_service_new(LassoServer *server, LassoDiscoResourceOffering *offering)
{
	LassoPersonalProfileService *service;

	g_return_val_if_fail(LASSO_IS_SERVER(server) == TRUE, NULL);

	service = g_object_new(LASSO_TYPE_PERSONAL_PROFILE_SERVICE, NULL);
	LASSO_WSF_PROFILE(service)->server = g_object_ref(server);
	lasso_data_service_set_offering(LASSO_DATA_SERVICE(service), offering);

	return service;
}
