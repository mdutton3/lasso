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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/id-wsf/discovery.h>
#include <lasso/id-wsf/profile_service.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>
#include <lasso/xml/soap_binding_correlation.h>


struct _LassoProfileServicePrivate
{
	gboolean dispose_has_run;
	LassoDiscoResourceOffering *offering;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoDstData*
lasso_profile_service_add_data(LassoProfileService *service, const gchar *xmlNodeBuffer)
{
	LassoWsfProfile *profile;
	LassoDstData *data;
	xmlNode *root, *xmlnode;
	xmlDoc *doc;
	
	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service) == TRUE, NULL);
	g_return_val_if_fail(xmlNodeBuffer != NULL, NULL);

	profile = LASSO_WSF_PROFILE(service);

	/* xmlBuffer must be parsed and set in LassoDstData */
	doc = xmlParseMemory(xmlNodeBuffer, strlen(xmlNodeBuffer));
	root = xmlDocGetRootElement(doc);
	xmlnode = xmlCopyNode(root, 1);

	data = lasso_dst_data_new();
	data->any = g_list_append(data->any, xmlnode);

	LASSO_DST_QUERY_RESPONSE(profile->response)->Data = \
		g_list_append(LASSO_DST_QUERY_RESPONSE(profile->response)->Data, data);

	return data;
}

LassoDstModification*
lasso_profile_service_add_modification(LassoProfileService *service, const gchar *select)
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
lasso_profile_service_add_query_item(LassoProfileService *service, const gchar *select)
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
	const gchar *prefix,
	const gchar *href,
	LassoDiscoResourceOffering *resourceOffering,
	LassoDiscoDescription *description,
	const gchar *select)
{
	LassoDstModification *modification;
	LassoWsfProfile *profile;

	LassoSoapEnvelope *envelope;
	LassoDstModify *modify;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description), NULL);

	profile = LASSO_WSF_PROFILE(service);

	/* init Modify */
	modification = lasso_dst_modification_new(select);

	modify = lasso_dst_modify_new(modification);
	profile->request = LASSO_NODE(modify);

	LASSO_DST_MODIFY(profile->request)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_MODIFY(profile->request)->hrefServiceType = g_strdup(href);

	envelope = lasso_wsf_profile_build_soap_envelope(NULL);
	LASSO_WSF_PROFILE(service)->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, modify);

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

#if 0
LassoDstQueryItem*
lasso_profile_service_init_query(LassoProfileService *service,
	const gchar *prefix,
	const gchar *href,
	LassoDiscoResourceOffering *resourceOffering,
	LassoDiscoDescription *description,
	const gchar *select)
{
	LassoDstQueryItem *query_item;
	LassoWsfProfile *profile;

	LassoSoapEnvelope *envelope;
	LassoDstQuery *query;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(service);
	
	/* init Query */
	query_item = lasso_dst_query_item_new(select);

	query = lasso_dst_query_new(query_item);
	profile->request = LASSO_NODE(query);

	LASSO_DST_QUERY(profile->request)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_QUERY(profile->request)->hrefServiceType = g_strdup(href);
	
	envelope = lasso_wsf_profile_build_soap_envelope(NULL);
	LASSO_WSF_PROFILE(service)->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, query);

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
#endif

gint
lasso_profile_service_init_query(LassoProfileService *service, const char *select)
{
	LassoWsfProfile *profile;
	LassoDstQuery *query;
	LassoDiscoResourceOffering *offering;
	LassoDiscoDescription *description;

	profile = LASSO_WSF_PROFILE(service);

	query = lasso_dst_query_new(lasso_dst_query_item_new(select));
	profile->request = LASSO_NODE(query);
	
	offering = service->private_data->offering;

	query->hrefServiceType = g_strdup(offering->ServiceInstance->ServiceType);
	if (strcmp(query->hrefServiceType, LASSO_PP_HREF) == 0)
		query->prefixServiceType = g_strdup(LASSO_PP_PREFIX);
	else if (strcmp(query->hrefServiceType, LASSO_EP_HREF) == 0)
		query->prefixServiceType = g_strdup(LASSO_EP_PREFIX);
	else {
		/* unknown service type, (needs registration mechanism) */
		return LASSO_ERROR_UNDEFINED;
	}

	if (offering->ResourceID) {
		query->ResourceID = g_object_ref(offering->ResourceID);
	} else if (offering->EncryptedResourceID) {
		query->EncryptedResourceID = g_object_ref(offering->EncryptedResourceID);
	} else {
		/* XXX: no resource id, implied:resource, etc. */
		return LASSO_ERROR_UNIMPLEMENTED;
	}

	profile->soap_envelope_request = lasso_wsf_profile_build_soap_envelope(NULL);
	profile->soap_envelope_request->Body->any = g_list_append(
			profile->soap_envelope_request->Body->any, query);

	description = lasso_discovery_get_description_auto(offering, LASSO_SECURITY_MECH_NULL);

	if (description->Endpoint != NULL) {
		profile->msg_url = g_strdup(description->Endpoint);
	} else {
		/* XXX: else, description->WsdlURLI, get endpoint automatically */
		return LASSO_ERROR_UNIMPLEMENTED;
	}

	return 0;
}


xmlNode*
lasso_profile_service_get_xmlNode(LassoProfileService *service,
	gchar *itemId)
{
	LassoDstQueryResponse *response;
	GList *datas;
	LassoDstData *data;
	xmlNode *node;
	
	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service) == TRUE, NULL);

	response = LASSO_DST_QUERY_RESPONSE(LASSO_WSF_PROFILE(service)->response);
	datas = response->Data;
	if (itemId != NULL) {
		while (datas != NULL) {
			data = datas->data;
			if (strcmp(data->itemIDRef, itemId) == 0) {
				break;
			}
			datas = datas->next;
		}
	}
	if (datas == NULL) {
		return NULL;
	}
	data = LASSO_DST_DATA(datas->data);
	node = (xmlNode *) data->any->data;

	return xmlCopyNode(node, 1);
}

gint
lasso_profile_service_process_modify_msg(LassoProfileService *service,
	const gchar *prefix, /* FIXME : must be get from message */
	const gchar *href,   /* FIXME : must be get from message */
	const gchar *modify_soap_msg)
{
	LassoDstModifyResponse *response;
	LassoSoapBindingCorrelation *correlation;
	LassoSoapEnvelope *envelope;
	LassoUtilityStatus *status;
	LassoWsfProfile *profile;
	gchar *messageId;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(modify_soap_msg != NULL, -1);

	profile = LASSO_WSF_PROFILE(service);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(modify_soap_msg));
	LASSO_WSF_PROFILE(service)->soap_envelope_request = envelope;
	LASSO_WSF_PROFILE(service)->request = LASSO_NODE(envelope->Body->any->data);

	correlation = envelope->Header->Other->data;
	messageId = correlation->messageID;
	envelope = lasso_wsf_profile_build_soap_envelope(messageId);
	LASSO_WSF_PROFILE(service)->soap_envelope_response = envelope;

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_dst_modify_response_new(status);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);
	LASSO_DST_MODIFY_RESPONSE(profile->response)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_MODIFY_RESPONSE(profile->response)->hrefServiceType = g_strdup(href);

	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return 0;
}

gint
lasso_profile_service_process_query_msg(LassoProfileService *service,
	const gchar *prefix, /* FIXME : must be get from message */
	const gchar *href,   /* FIXME : must be get from message */
	const gchar *soap_msg)
{
	LassoDstQueryResponse *response;
	LassoSoapEnvelope *envelope;
	LassoUtilityStatus *status;
	LassoWsfProfile *profile;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(soap_msg != NULL, -1);

	profile = LASSO_WSF_PROFILE(service);

	lasso_wsf_profile_process_soap_request_msg(profile, soap_msg);

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_dst_query_response_new(status);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);
	LASSO_DST_QUERY_RESPONSE(profile->response)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_QUERY_RESPONSE(profile->response)->hrefServiceType = g_strdup(href);

	envelope = profile->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return 0;
}


gint
lasso_profile_service_process_query_response_msg(LassoProfileService *service,
	const gchar *prefix,
	const gchar *href,
	const gchar *soap_msg)
{
	LassoDstQueryResponse *response;
	LassoSoapEnvelope *envelope;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(soap_msg != NULL, -1);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(soap_msg));
	LASSO_WSF_PROFILE(service)->soap_envelope_response = envelope;

	response = envelope->Body->any->data;
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);

	return 0;
}

gint
lasso_profile_service_process_modify_response_msg(LassoProfileService *service,
	const gchar *prefix,
	const gchar *href,
	const gchar *soap_msg)
{
	LassoDstModifyResponse *response;
	LassoSoapEnvelope *envelope;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(soap_msg != NULL, -1);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(soap_msg));
	LASSO_WSF_PROFILE(service)->soap_envelope_response = envelope;

	response = envelope->Body->any->data;
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);

	return 0;
}

gint
lasso_profile_service_validate_modify(LassoProfileService *service,
	const gchar *prefix,
	const gchar *href)
{

	return -1;
}

gint
lasso_profile_service_validate_query(LassoProfileService *service,
	const gchar *prefix,
	const gchar *href)
{
	LassoDstQuery *request;
	LassoDstQueryResponse *response;
	GList *queryItems;
	LassoDstQueryItem *queryItem;
	char *select;
	
	xmlNode *xmlnode;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	char *data;
	LassoDstData *dstData;

	xmlOutputBuffer *buf;


	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service) == TRUE, -1);

	request = LASSO_DST_QUERY(LASSO_WSF_PROFILE(service)->request);
	response = LASSO_DST_QUERY_RESPONSE(LASSO_WSF_PROFILE(service)->response);

	queryItems = request->QueryItem;
	while (queryItems) {
		queryItem = LASSO_DST_QUERY_ITEM(queryItems->data);
		select = queryItem->Select;

		xpathCtx = xmlXPathNewContext(LASSO_PROFILE_SERVICE(service)->profileDataXmlDoc);
		xmlXPathRegisterNs(xpathCtx, (xmlChar *) prefix, (xmlChar *) href);
		xpathObj = xmlXPathEvalExpression((xmlChar *) select, xpathCtx);
		if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
			xmlnode = xpathObj->nodesetval->nodeTab[0];
			buf = xmlAllocOutputBuffer(NULL);
			if (buf == NULL) {
				continue;
			}
			xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 1, NULL);
			xmlOutputBufferFlush(buf);
			if (buf->conv != NULL) {
				data = g_strdup((gchar *) buf->conv->content);
			} else {
				data = g_strdup((gchar *) buf->buffer->content);
			}
			
			dstData = lasso_profile_service_add_data(LASSO_PROFILE_SERVICE(service),
				data);
			if (queryItem->itemID != NULL) {
				dstData->itemIDRef = g_strdup(queryItem->itemID);
			}

			xmlOutputBufferClose(buf);
			xmlFreeNode(xmlnode);
		}
		xmlXPathFreeContext(xpathCtx);
		xmlXPathFreeObject(xpathObj);

		queryItems = queryItems->next;
	}
	
	return 0;
}

gint
lasso_profile_service_set_xml_node(LassoProfileService *service,
	const char *prefix,
	const char *href,
	xmlNodePtr xmlNode)
{
	xmlNsPtr ns;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service) == TRUE, -1);
	g_return_val_if_fail(xmlNode != NULL, -1);

	ns = xmlNewNs(xmlNode, (const xmlChar *) href, (const xmlChar *) prefix);
	xmlSetNs(xmlNode, ns);
	service->profileDataXmlDoc = xmlNewDoc((const xmlChar *) "1.0");
	xmlDocSetRootElement(service->profileDataXmlDoc, xmlNode);

	return 0;
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
	LassoProfileService *service = LASSO_PROFILE_SERVICE(object);

	if (service->private_data->dispose_has_run == TRUE)
		return;
	service->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoProfileService *service = LASSO_PROFILE_SERVICE(object);
	if (service->private_data->offering) {
		lasso_node_destroy(LASSO_NODE(service->private_data->offering));
		service->private_data->offering = NULL;
	}
	g_free(service->private_data);
	service->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoProfileService *service)
{
	service->profileDataXmlDoc = NULL;
	service->private_data = g_new0(LassoProfileServicePrivate, 1);
}

static void
class_init(LassoProfileServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	
	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
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
	LassoProfileService *service;

	g_return_val_if_fail(LASSO_IS_SERVER(server) == TRUE, NULL);

	service = g_object_new(LASSO_TYPE_PROFILE_SERVICE, NULL);
	LASSO_WSF_PROFILE(service)->server = g_object_ref(server);

	return service;
}

LassoProfileService*
lasso_profile_service_new_full(LassoServer *server, LassoDiscoResourceOffering *offering)
{
	LassoProfileService *service;

	service = lasso_profile_service_new(server);
	if (service == NULL)
		return NULL;
	
	service->private_data->offering = g_object_ref(offering);

	return service;
}

