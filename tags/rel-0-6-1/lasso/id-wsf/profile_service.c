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

#include <lasso/id-wsf/profile_service.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_profile_service_add_data(LassoProfileService *service, const char *xmlNodeBuffer)
{
	LassoWsfProfile *profile;
	LassoDstData *data;
	xmlNode *root, *xmlnode;
	xmlDoc *doc;
	
	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service) == TRUE, -1);
	g_return_val_if_fail(xmlNodeBuffer != NULL, -1);

	profile = LASSO_WSF_PROFILE(service);

	/* xmlBuffer must be parsed and set in LassoDstData */
	doc = xmlParseMemory(xmlNodeBuffer, strlen(xmlNodeBuffer));
	root = xmlDocGetRootElement(doc);
	xmlnode = xmlCopyNode(root, 1);

	data = lasso_dst_data_new();
	data->any = g_list_append(data->any, xmlnode);

	LASSO_DST_QUERY_RESPONSE(profile->response)->Data = \
		g_list_append(LASSO_DST_QUERY_RESPONSE(profile->response)->Data, data);

	return 0;
}

LassoDstModification*
lasso_profile_service_add_modification(LassoProfileService *service, const char *select)
{
	LassoWsfProfile *profile;
	LassoDstModification *modification;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(service);

	modification = lasso_dst_modification_new(select);
	LASSO_DST_MODIFY(profile->request)->Modification = g_list_append(
		LASSO_DST_MODIFY(profile->request)->Modification, (gpointer)modification);

	return modification;
}

LassoDstQueryItem*
lasso_profile_service_add_query_item(LassoProfileService *service, const char *select)
{
	LassoWsfProfile *profile;
	LassoDstQueryItem *query_item;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(service);

	query_item = lasso_dst_query_item_new(select);
	LASSO_DST_QUERY(profile->request)->QueryItem = g_list_append(
		LASSO_DST_QUERY(profile->request)->QueryItem, (gpointer)query_item);

	return query_item;
}

LassoDstModification*
lasso_profile_service_init_modify(LassoProfileService *service,
				  const char *prefix,
				  const char *href,
				  LassoDiscoResourceOffering *resourceOffering,
				  LassoDiscoDescription *description,
				  const char *select)
{
	LassoDstModification *modification;
	LassoWsfProfile *profile;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description), NULL);

	profile = LASSO_WSF_PROFILE(service);

	/* init Modify */
	modification = lasso_dst_modification_new(select);
	profile->request = LASSO_NODE(lasso_dst_modify_new(modification));
	LASSO_DST_MODIFY(profile->request)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_MODIFY(profile->request)->hrefServiceType = g_strdup(href);

	/* get ResourceID / EncryptedResourceID */
	if (resourceOffering->ResourceID != NULL) {
		LASSO_DST_MODIFY(profile->request)->ResourceID = resourceOffering->ResourceID;
	}
	else {
	  LASSO_DST_MODIFY(profile->request)->EncryptedResourceID = \
		  resourceOffering->EncryptedResourceID;
	}

	/* set msg_url */
	/* TODO : implement WSDLRef */
	if (description->Endpoint) {
		profile->msg_url = g_strdup(description->Endpoint);
	}

	return modification;
}

LassoDstQueryItem*
lasso_profile_service_init_query(LassoProfileService *service,
				 const char *prefix,
				 const char *href,
				 LassoDiscoResourceOffering *resourceOffering,
				 LassoDiscoDescription *description,
				 const char *select)
{
	LassoDstQueryItem *query_item;
	LassoWsfProfile *profile;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(service);
	
	/* init Query */
	query_item = lasso_dst_query_item_new(select);
	profile->request = LASSO_NODE(lasso_dst_query_new(query_item));
	LASSO_DST_QUERY(profile->request)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_QUERY(profile->request)->hrefServiceType = g_strdup(href);
	
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
	if (description->Endpoint) {
		profile->msg_url = g_strdup(description->Endpoint);
	}

	return query_item;
}

gint
lasso_profile_service_process_modify_msg(LassoProfileService *service,
					 const char *prefix, /* FIXME : must be get from message */
					 const char *href,   /* FIXME : must be get from message */
					 const char *modify_soap_msg)
{
	LassoDstModify *modify;
	LassoWsfProfile *profile;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(modify_soap_msg != NULL, -1);

	profile = LASSO_WSF_PROFILE(service);

	modify = g_object_new(LASSO_TYPE_DST_MODIFY, NULL);
	lasso_node_init_from_message(LASSO_NODE(modify), modify_soap_msg);

	profile->request = LASSO_NODE(modify);

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(lasso_dst_modify_response_new(status));
	LASSO_DST_MODIFY_RESPONSE(profile->response)->prefixServiceType = \
		g_strdup(prefix);
	LASSO_DST_MODIFY_RESPONSE(profile->response)->hrefServiceType = \
		g_strdup(href);

	return 0;
}

gint
lasso_profile_service_process_query_msg(LassoProfileService *service,
					const char *prefix, /* FIXME : must be get from message */
					const char *href,   /* FIXME : must be get from message */
					const char *query_soap_msg)
{
	LassoDstQuery *query;
	LassoWsfProfile *profile;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(query_soap_msg != NULL, -1);

	profile = LASSO_WSF_PROFILE(service);

	query = g_object_new(LASSO_TYPE_DST_QUERY, NULL);
	lasso_node_init_from_message(LASSO_NODE(query), query_soap_msg);

	profile->request = LASSO_NODE(query);

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(lasso_dst_query_response_new(status));
	LASSO_DST_QUERY_RESPONSE(profile->response)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_QUERY_RESPONSE(profile->response)->hrefServiceType = g_strdup(href);

	return 0;
}

gint
lasso_profile_service_process_query_response_msg(LassoProfileService *service,
						 const char *prefix,
						 const char *href,
						 const char *query_response_soap_msg)
{
	LassoDstQueryResponse *query_response;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(query_response_soap_msg != NULL, -1);

	query_response = g_object_new(LASSO_TYPE_DST_QUERY_RESPONSE, NULL);
	lasso_node_init_from_message(LASSO_NODE(query_response), query_response_soap_msg);

	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(query_response);

	return 0;
}

gint
lasso_profile_service_process_modify_response_msg(LassoProfileService *service,
						  const char *prefix,
						  const char *href,
						  const char *modify_response_soap_msg)
{
	LassoDstModifyResponse *modify_response;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(modify_response_soap_msg != NULL, -1);

	modify_response = g_object_new(LASSO_TYPE_DST_MODIFY_RESPONSE, NULL);
	lasso_node_init_from_message(LASSO_NODE(modify_response), modify_response_soap_msg);

	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(modify_response);

	return 0;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoProfileService *service)
{

}

static void
class_init(LassoProfileServiceClass *klass)
{

}

GType
lasso_profile_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoProfileServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoProfileService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
				"LassoProfileService", &this_info, 0);
	}
	return this_type;
}

LassoProfileService*
lasso_profile_service_new(LassoServer *server)
{
	LassoProfileService *service = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server) == TRUE, NULL);

	service = g_object_new(LASSO_TYPE_PROFILE_SERVICE, NULL);

	return service;
}
