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
#include <lasso/xml/dst_query_response.h>
#include <lasso/xml/dst_data.h>


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoDstModification*
lasso_personal_profile_service_init_modify(LassoPersonalProfileService *service,
	LassoDiscoResourceOffering *resourceOffering,
	LassoDiscoDescription *description,
	const gchar *select)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, NULL);

	return lasso_profile_service_init_modify(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF,
				resourceOffering,
				description,
				select);
}

LassoDstQueryItem*
lasso_personal_profile_service_init_query(LassoPersonalProfileService *service,
	LassoDiscoResourceOffering *resourceOffering,
	LassoDiscoDescription *description,
	const gchar *select)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, NULL);

	return NULL;
#if 0 /* XXX */
	return lasso_profile_service_init_query(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF,
				resourceOffering,
				description,
				select);
#endif
}

gchar*
lasso_personal_profile_service_get_email(LassoPersonalProfileService *service)
{
	LassoDstQueryResponse *response;
	GList *datas;
	LassoDstData *data;
	xmlNode *root, *child;
	xmlChar *msgAccount, *msgProvider;
	char *email;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, NULL);

	response = LASSO_DST_QUERY_RESPONSE(LASSO_WSF_PROFILE(service)->response);
	datas = response->Data;
	msgAccount = NULL;
	msgProvider = NULL;
	while (datas != NULL) {
		data = LASSO_DST_DATA(datas->data);

		root = (xmlNode *) data->any->data;
		if (root == NULL) {
			printf("\tDEBUG - Root element not found ...\n");
			datas = datas->next;
			continue;
		}

		if (strcmp((char *) root->name, "MsgContact") == 0) {
			child = root->children;
			while (child != NULL) {
				if (child->type != XML_ELEMENT_NODE) {
					child = child->next;
					continue;
				}

				if (strcmp((char *) child->name, "MsgAccount") == 0) {
					msgAccount = xmlNodeGetContent(child);
				}
				else if (strcmp((char *) child->name, "MsgProvider") == 0) {
					msgProvider = xmlNodeGetContent(child);
				}
				
				if (msgAccount != NULL && msgProvider != NULL) {
					break;
				}
		
				child = child->next;
			}
		}

		if (msgAccount != NULL && msgProvider != NULL) {
			break;
		}

		datas = datas->next;
	}
	if (msgAccount != NULL || msgProvider != NULL) {
		email = g_strdup_printf("%s@%s", msgAccount, msgProvider);
	}
	xmlFree(msgAccount);
	xmlFree(msgProvider);

	return email;
}

gint
lasso_personal_profile_service_process_modify_msg(LassoPersonalProfileService *service,
	const gchar *modify_soap_msg)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);

	return lasso_profile_service_process_modify_msg(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF,
				modify_soap_msg);
}

gint
lasso_personal_profile_service_process_query_msg(LassoPersonalProfileService *service,
	const gchar *soap_msg)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);

	return lasso_profile_service_process_query_msg(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF,
				soap_msg);
}

gint
lasso_personal_profile_service_process_query_response_msg(LassoPersonalProfileService *service,
	const gchar *soap_msg)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);

	return lasso_profile_service_process_query_response_msg(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF,
				soap_msg);
}

gint
lasso_personal_profile_service_process_modify_response_msg(LassoPersonalProfileService *service,
	const gchar *soap_msg)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);

	return lasso_profile_service_process_modify_response_msg(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF,
				soap_msg);
}

gint
lasso_personal_profile_service_validate_modify(LassoPersonalProfileService *service)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);

	return lasso_profile_service_validate_modify(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF);
}

gint
lasso_personal_profile_service_validate_query(LassoPersonalProfileService *service)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);

	return lasso_profile_service_validate_query(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX,
				LASSO_PP_HREF);
}

gint
lasso_personal_profile_service_set_xml_node(LassoPersonalProfileService *service,
	xmlNodePtr xmlNode)
{
	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(service) == TRUE, -1);
	g_return_val_if_fail(xmlNode != NULL, -1);

	return lasso_profile_service_set_xml_node(LASSO_PROFILE_SERVICE(service),
				LASSO_PP_PREFIX, LASSO_PP_HREF, xmlNode);
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
lasso_personal_profile_service_new(LassoServer *server)
{
	LassoPersonalProfileService *service = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server) == TRUE, NULL);

	return g_object_new(LASSO_TYPE_PERSONAL_PROFILE_SERVICE, NULL);
}
