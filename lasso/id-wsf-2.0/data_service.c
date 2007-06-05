/* $Id: idwsf2_data_service.c 3101 2007-05-30 11:40:10Z dlaniel $
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

/* #include <libxml/xpath.h> */

#include <lasso/id-wsf-2.0/discovery.h>
#include <lasso/id-wsf-2.0/data_service.h>

#include <lasso/xml/id-wsf-2.0/dstref_query.h>
/* #include <lasso/xml/id-wsf-2.0/dstref_query_response.h> */

#include <lasso/xml/id-wsf-2.0/disco_service_type.h>

struct _LassoIdWsf2DataServicePrivate
{
	gboolean dispose_has_run;
	LassoWsAddrEndpointReference *epr;
	GList *credentials;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_idwsf2_data_service_init_query(LassoIdWsf2DataService *service)
{
	LassoWsf2Profile *profile;
	LassoIdWsf2DstRefQuery *query;
	LassoWsAddrEndpointReference *epr;
	GList *metadata_item;
	GList *i;
	gchar *service_type = NULL;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile = LASSO_WSF2_PROFILE(service);

	query = lasso_idwsf2_dstref_query_new();

	profile->request = LASSO_NODE(query);

	if (service == NULL || service->private_data == NULL
			|| service->private_data->epr == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE;
	}

	epr = service->private_data->epr;

	/* Get the service type from the EPR */
	metadata_item = epr->Metadata->any;
	for (i = g_list_first(metadata_item); i != NULL; i = g_list_next(i)) {
		if (LASSO_IS_IDWSF2_DISCO_SERVICE_TYPE(i->data)) {
			service_type = LASSO_IDWSF2_DISCO_SERVICE_TYPE(i->data)->content;
			break;
		}
	}

	/* Set hrefServiceType and prefixServiceType in query in order to set the profile */
	/* namespace in the request */
	if (service_type != NULL) {
		query->hrefServiceType = g_strdup(service_type);
		query->prefixServiceType = lasso_get_prefix_for_idwsf2_dst_service_href(
			query->hrefServiceType);
	}
	if (query->prefixServiceType == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE;
	}

	lasso_wsf2_profile_init_soap_request(profile, LASSO_NODE(query));

	/* Set msg_url as epr address, which is the SoapEndpoint */
	if (epr->Address != NULL) {
		profile->msg_url = g_strdup(epr->Address->content);
	} else {
		return LASSO_PROFILE_ERROR_MISSING_ENDPOINT_REFERENCE_ADDRESS;
	}

	return 0;
}

gint
lasso_idwsf2_data_service_add_query_item(LassoIdWsf2DataService *service, const gchar *item_xpath,
	const gchar *item_id)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(service);
	LassoIdWsf2DstRefQuery *query;
	LassoIdWsf2DstRefQueryItem *item;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(item_xpath != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(item_id != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (! LASSO_IS_IDWSF2_DSTREF_QUERY(profile->request)) {
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}

	query = LASSO_IDWSF2_DSTREF_QUERY(profile->request);

	item = lasso_idwsf2_dstref_query_item_new_full(item_xpath, item_id);
	query->QueryItem = g_list_append(query->QueryItem, item);

	return 0;
}

gint
lasso_idwsf2_data_service_process_query_msg(LassoIdWsf2DataService *service, const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(service);
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	res = lasso_wsf2_profile_process_soap_request_msg(profile, message);

	service->type = g_strdup(LASSO_IDWSF2_DSTREF_QUERY(profile->request)->hrefServiceType);
	printf(LASSO_IDWSF2_DSTREF_QUERY(profile->request)->prefixServiceType);
	return res;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoIdWsf2DataService *service = LASSO_IDWSF2_DATA_SERVICE(object);

	if (service->private_data->dispose_has_run == TRUE)
		return;
	service->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoIdWsf2DataService *service = LASSO_IDWSF2_DATA_SERVICE(object);
	if (service->private_data->epr) {
		lasso_node_destroy(LASSO_NODE(service->private_data->epr));
		service->private_data->epr = NULL;
	}
	g_free(service->private_data);
	service->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2DataService *service)
{
	service->data = NULL;
	service->type = NULL;
	service->private_data = g_new0(LassoIdWsf2DataServicePrivate, 1);
	service->private_data->epr = NULL;
}

static void
class_init(LassoIdWsf2DataServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	
	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_idwsf2_data_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoIdWsf2DataServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2DataService),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF2_PROFILE,
				"LassoIdWsf2DataService", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_idwsf2_data_service_new:
 *
 * Creates a new #LassoIdWsf2DataService.
 *
 * Return value: a newly created #LassoIdWsf2DataService object
 **/
LassoIdWsf2DataService*
lasso_idwsf2_data_service_new(LassoServer *server)
{
	LassoIdWsf2DataService *service;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	service = g_object_new(LASSO_TYPE_IDWSF2_DATA_SERVICE, NULL);

	LASSO_WSF2_PROFILE(service)->server = g_object_ref(server);

	return service;
}

LassoIdWsf2DataService*
lasso_idwsf2_data_service_new_full(LassoServer *server, LassoWsAddrEndpointReference *epr)
{
	LassoIdWsf2DataService *service;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
	g_return_val_if_fail(LASSO_IS_WSA_ENDPOINT_REFERENCE(epr), NULL);

	service = lasso_idwsf2_data_service_new(server);

	service->private_data->epr = g_object_ref(epr);

	return service;
}

