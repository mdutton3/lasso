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

#include <lasso/xml/disco_resource_offering.h>
#include <lasso/xml/dst_data.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/id-wsf/personal_profile_service.h>

struct _LassoPersonalProfileServicePrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_personal_profile_service_add_data(LassoPersonalProfileService *pp, LassoNode *requested_data)
{
	LassoWsfProfile *profile;
	LassoDstData *data;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(pp) == TRUE, -1);
	g_return_val_if_fail(LASSO_IS_NODE(requested_data) == TRUE, -1);

	profile = LASSO_WSF_PROFILE(pp);

	data = lasso_dst_data_new();
	data->any = g_list_append(data->any, requested_data);

	LASSO_DST_QUERY_RESPONSE(profile->response)->Data = \
		g_list_append(LASSO_DST_QUERY_RESPONSE(profile->response)->Data, data);

	return 0;
}

LassoDstQueryItem*
lasso_personal_profile_service_add_query_item(LassoPersonalProfileService *pp, const char *select)
{
	LassoWsfProfile *profile;
	LassoDstQueryItem *query_item;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(pp), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(pp);

	query_item = lasso_dst_query_item_new(select);
	LASSO_DST_QUERY(profile->request)->QueryItem = g_list_append(
		LASSO_DST_QUERY(profile->request)->QueryItem, (gpointer)query_item);

	return query_item;
}

LassoDstQueryItem*
lasso_personal_profile_service_init_query(LassoPersonalProfileService *pp,
					  LassoDiscoResourceOffering *resourceOffering,
					  LassoDiscoDescription *description,
					  const char *select)
{
	LassoDstQueryItem *query_item;
	LassoWsfProfile *profile;
	LassoAbstractService *service;
	GList *l_desc;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(pp), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(pp);
	service = LASSO_ABSTRACT_SERVICE(pp);
	
	/* init Query */
	query_item = lasso_dst_query_item_new(select);
	profile->request = LASSO_NODE(lasso_dst_query_new(query_item));
	LASSO_DST_QUERY(profile->request)->prefixServiceType = LASSO_PP_PREFIX;
	LASSO_DST_QUERY(profile->request)->hrefServiceType = LASSO_PP_HREF;
	
	/* get ResourceID / EncryptedResourceID */
	if (resourceOffering->ResourceID != NULL) {
		LASSO_DST_QUERY(profile->request)->ResourceID = resourceOffering->ResourceID;
	}
	else {
	  LASSO_DST_QUERY(profile->request)->EncryptedResourceID = \
		  resourceOffering->EncryptedResourceID;
	}
	
	/* set msg_url */
	/* TODO : implement WSDLRef */
	l_desc = resourceOffering->ServiceInstance->Description;
	while (l_desc != NULL) {
		l_desc = l_desc->next;
	}
	if (description->Endpoint) {
		profile->msg_url = g_strdup(description->Endpoint);
	}

	return query_item;
}

gint
lasso_personal_profile_service_process_request_msg(LassoPersonalProfileService *pp,
						   const char *query_soap_msg)
{
	LassoDstQuery *query;
	LassoDstQueryItem *query_item;
	LassoDstQueryResponse *query_response;
	LassoWsfProfile *profile;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(pp), -1);
	g_return_val_if_fail(query_soap_msg != NULL, -1);

	profile = LASSO_WSF_PROFILE(pp);

	query = g_object_new(LASSO_TYPE_DST_QUERY, NULL);
	lasso_node_init_from_message(LASSO_NODE(query), query_soap_msg);

	/* get ResourceIDGroup */
	if (query->ResourceID) {
		LASSO_ABSTRACT_SERVICE(pp)->ResourceID = query->ResourceID;
	}
	else {
		LASSO_ABSTRACT_SERVICE(pp)->EncryptedResourceID = query->EncryptedResourceID;
	}

	/* get QueryItems */
	LASSO_ABSTRACT_SERVICE(pp)->queryItem = query->QueryItem;

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	LASSO_WSF_PROFILE(pp)->response = LASSO_NODE(lasso_dst_query_response_new(status));
	LASSO_DST_QUERY_RESPONSE(profile->response)->prefixServiceType = LASSO_PP_PREFIX;
	LASSO_DST_QUERY_RESPONSE(profile->response)->hrefServiceType = LASSO_PP_HREF;

	return 0;
}

gint
lasso_personal_profile_service_process_response_msg(LassoPersonalProfileService *pp,
						    const char *query_response_soap_msg)
{
	LassoDstQueryResponse *query_response;
	GList *Data;

	g_return_val_if_fail(LASSO_IS_PERSONAL_PROFILE_SERVICE(pp), -1);
	g_return_val_if_fail(query_response_soap_msg != NULL, -1);

	query_response = g_object_new(LASSO_TYPE_DST_QUERY_RESPONSE, NULL);
	lasso_node_init_from_message(LASSO_NODE(query_response), query_response_soap_msg);

	LASSO_WSF_PROFILE(pp)->response = LASSO_NODE(query_response);

	LASSO_ABSTRACT_SERVICE(pp)->data = query_response->Data;

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoPersonalProfileServiceClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoPersonalProfileService *pp)
{

}

static void
class_init(LassoPersonalProfileServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

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

		this_type = g_type_register_static(LASSO_TYPE_ABSTRACT_SERVICE,
				"LassoPersonalProfileService", &this_info, 0);
	}
	return this_type;
}

LassoPersonalProfileService*
lasso_personal_profile_service_new(LassoServer *server)
{
	LassoPersonalProfileService *pp = NULL;

/* 	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL); */

	pp = g_object_new(LASSO_TYPE_PERSONAL_PROFILE_SERVICE, NULL);

	return pp;
}
