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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/id-wsf-2.0/discovery.h>
#include <lasso/id-wsf-2.0/data_service.h>

#include <lasso/xml/id-wsf-2.0/disco_service_type.h>
#include <lasso/xml/id-wsf-2.0/dstref_query.h>
#include <lasso/xml/id-wsf-2.0/dstref_query_response.h>
#include <lasso/xml/id-wsf-2.0/dstref_data.h>
#include <lasso/xml/id-wsf-2.0/util_status.h>

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
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(service);
	LassoIdWsf2DstRefQuery *query;
	LassoWsAddrEndpointReference *epr;
	GList *metadata_item;
	GList *i;
	gchar *service_type = NULL;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	query = lasso_idwsf2_dstref_query_new();

	if (profile->request) {
		lasso_node_destroy(LASSO_NODE(profile->request));
	}
	profile->request = LASSO_NODE(query);

	if (service == NULL || service->private_data == NULL
			|| service->private_data->epr == NULL
			|| service->private_data->epr->Metadata == NULL) {
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

	lasso_wsf2_profile_init_soap_request(profile, LASSO_NODE(query), service_type);

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

	if (! LASSO_IS_IDWSF2_DSTREF_QUERY(profile->request)) {
		res = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	} else {
		service->type = g_strdup(
			LASSO_IDWSF2_DSTREF_QUERY(profile->request)->hrefServiceType);
	}

	return res;
}

gint
lasso_idwsf2_data_service_build_query_response_msg(LassoIdWsf2DataService *service)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(service);
	LassoIdWsf2DstRefQuery *request;
	LassoIdWsf2DstRefQueryResponse *response;
	LassoIdWsf2UtilResponse *response2;
	LassoSoapEnvelope *envelope;
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	LassoIdWsf2DstRefQueryItem *item;
	LassoIdWsf2DstRefResultQuery *item_result_query;
	LassoIdWsf2DstResultQueryBase *item_result_query_base;
	LassoIdWsf2DstRefData *data;
	LassoIdWsf2DstRefItemData *data_item;
	xmlNode *node;
	GList *iter;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (! LASSO_IS_IDWSF2_DSTREF_QUERY(profile->request)) {
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}
	request = LASSO_IDWSF2_DSTREF_QUERY(profile->request);

	/* Response envelope and body */
	envelope = profile->soap_envelope_response;
	response = lasso_idwsf2_dstref_query_response_new();
	response->prefixServiceType = g_strdup(request->prefixServiceType);
	response->hrefServiceType = g_strdup(request->hrefServiceType);
	profile->response = LASSO_NODE(response);
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	response2 = LASSO_IDWSF2_UTIL_RESPONSE(response);
	/* Default is Failed, will be OK or Partial when some items are successfully parsed */
	response2->Status = lasso_util_status_new(LASSO_DST_STATUS_CODE_FAILED);

	/* Initialise XML parsing */
	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, service->data);
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)response->prefixServiceType,
		(xmlChar*)response->hrefServiceType);

	/* Parse request QueryItems and fill response Data accordingly */
	/* XXX: needs another level, since there may be more than one <dst:Query> */
	for (iter = g_list_first(request->QueryItem); iter != NULL; iter = g_list_next(iter)) {
		item = iter->data;
		item_result_query = LASSO_IDWSF2_DSTREF_RESULT_QUERY(item);
		item_result_query_base = LASSO_IDWSF2_DST_RESULT_QUERY_BASE(item);
		xpathObj = xmlXPathEvalExpression((xmlChar*)item_result_query->Select, xpathCtx);
		if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
			/* XXX: assuming there is only one matching node */
			node = xpathObj->nodesetval->nodeTab[0];
			data = lasso_idwsf2_dstref_data_new();
			data_item = LASSO_IDWSF2_DSTREF_ITEM_DATA(data);
			data_item->any = g_list_append(data_item->any, xmlCopyNode(node, 1));
			if (item_result_query_base->itemID != NULL) {
				data_item->itemIDRef = g_strdup(item_result_query_base->itemID);
			}
			response->Data = g_list_append(response->Data, data);
			/* Success : change status code to OK */
			if (strcmp(response2->Status->code, LASSO_DST_STATUS_CODE_FAILED) == 0) {
				free(response2->Status->code);
				response2->Status->code = g_strdup(LASSO_DST_STATUS_CODE_OK);
			}
			xmlXPathFreeObject(xpathObj);
			xpathObj = NULL;
		} else {
			/* If status was OK, change it to Partial */
			if (strcmp(response2->Status->code, LASSO_DST_STATUS_CODE_OK) == 0) {
				free(response2->Status->code);
				response2->Status->code = g_strdup(LASSO_DST_STATUS_CODE_PARTIAL);
			} else {
				res = LASSO_DST_ERROR_QUERY_FAILED;
			}
			if (xpathObj != NULL) {
				xmlXPathFreeObject(xpathObj);
				xpathObj = NULL;
			}
			/* Stop processing at first error */
			break;
		}
	}
	/* Free XML parsing objects */
	xmlUnlinkNode(service->data);
	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);

	if (res == 0 && strcmp(response2->Status->code, LASSO_DST_STATUS_CODE_FAILED) == 0) {
		res = LASSO_DST_ERROR_QUERY_FAILED;
	}

	lasso_wsf2_profile_build_response_msg(profile);

	return res;
}

gint
lasso_idwsf2_data_service_process_query_response_msg(LassoIdWsf2DataService *service,
	const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(service);
	LassoIdWsf2UtilResponse *response;
	int res;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	res = lasso_wsf2_profile_process_soap_response_msg(profile, message);
	if (res != 0) {
		return res;
	}
	
	if (! LASSO_IS_IDWSF2_DSTREF_QUERY_RESPONSE(profile->response)) {
		return LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* Check response status code */
	response = LASSO_IDWSF2_UTIL_RESPONSE(profile->response);
	if (response->Status == NULL || response->Status->code == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}
	if (strcmp(response->Status->code, LASSO_DST_STATUS_CODE_PARTIAL) == 0) {
		return LASSO_DST_ERROR_QUERY_PARTIALLY_FAILED;
	} else if (strcmp(response->Status->code, LASSO_DST_STATUS_CODE_OK) != 0) {
		return LASSO_DST_ERROR_QUERY_FAILED;
	}

	return 0;
}

xmlNode*
lasso_idwsf2_data_service_get_attribute_node(LassoIdWsf2DataService *service, const gchar *item_id)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(service);
	LassoIdWsf2DstRefQueryResponse *response;
	LassoIdWsf2DstRefItemData *data = NULL;
	GList *iter;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service), NULL);

	response = LASSO_IDWSF2_DSTREF_QUERY_RESPONSE(profile->response);

	/* If no item_id is given, return the first item */
	if (item_id == NULL && response->Data != NULL && response->Data->data != NULL) {
		data = LASSO_IDWSF2_DSTREF_ITEM_DATA(response->Data->data);
		if (data->any != NULL && data->any->data != NULL) {
			return xmlCopyNode(data->any->data, 1);
		}
	}
	if (item_id == NULL) {
		return NULL;
	}

	/* Find the item which has the given item_id */
	for (iter = g_list_first(response->Data); iter != NULL; iter = g_list_next(iter)) {
		if (! LASSO_IS_IDWSF2_DSTREF_ITEM_DATA(iter->data)) {
			continue;
		}
		if (strcmp(LASSO_IDWSF2_DSTREF_ITEM_DATA(iter->data)->itemIDRef, item_id) == 0) {
			data = LASSO_IDWSF2_DSTREF_ITEM_DATA(iter->data);
			break;
		}
	}

	if (data == NULL || data->any == NULL || data->any->data == NULL) {
		/* Item not found */
		return NULL;
	}

	/* XXX: there may be more than one xmlnode */
	return xmlCopyNode(data->any->data, 1);
}

gchar*
lasso_idwsf2_data_service_get_attribute_string(LassoIdWsf2DataService *service,
	const gchar *item_id)
{
	xmlNode *node;
	xmlChar *xml_content;
	gchar *content;
	
	g_return_val_if_fail(LASSO_IS_IDWSF2_DATA_SERVICE(service), NULL);
	
	node = lasso_idwsf2_data_service_get_attribute_node(service, item_id);
	xml_content = xmlNodeGetContent(node);
	content = g_strdup((gchar*)xml_content);

	xmlFree(xml_content);
	xmlFreeNode(node);

	return content;
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

