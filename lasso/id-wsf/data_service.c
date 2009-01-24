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

/**
 * SECTION:data_service
 * @short_description: ID-WSF Data Service Profile
 *
 * Following up on #LassoDiscovery first example, it created a @service object,
 * this is a #LassoDataService instance.  This example continues from that step
 * and retrieves the name of the principal:
 *
 * <informalexample>
 * <programlisting>
 * char *soap_answer;            // SOAP answer from data service
 * xmlNode *principal_name;      // libxml2 xmlNode with the principal name
 *
 * service = lasso_discovery_get_service(discovery);
 * lasso_data_service_init_query(service, "/pp:PP/pp:InformalName", NULL);
 * lasso_data_service_build_request_msg(service);
 *
 * // service must perform SOAP call to LASSO_WSF_PROFILE(service)->msg_url
 * // the SOAP message is LASSO_WSF_PROFILE(service)->msg_body.  The answer
 * // is stored in char* soap_answer;
 *
 * lasso_data_service_process_query_response_msg(service, soap_answer);
 * principal_name = lasso_data_service_get_answer(service, "/pp:PP/pp:InformalName");
 *
 * // app should probably then use xmlNodeGetContent libxml2 function to get
 * // access to node content.
 * </programlisting>
 * </informalexample>
 *
 */

#include "../utils.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/id-wsf/discovery.h>
#include <lasso/id-wsf/data_service.h>
#include <lasso/id-wsf/data_service_private.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_fault.h>
#include <lasso/xml/is_redirect_request.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

extern GHashTable *dst_services_by_prefix; /* cf xml/xml.c */

struct _LassoDataServicePrivate
{
	gboolean dispose_has_run;
	LassoDiscoResourceOffering *offering;
	GList *credentials;
	LassoSoapFault *fault;
};

static void lasso_register_idwsf_xpath_namespaces(xmlXPathContext *xpathCtx);

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_data_service_add_credential(LassoDataService *service,
	LassoSamlAssertion *assertion)
{
	service->private_data->credentials = g_list_append(
		service->private_data->credentials,
		g_object_ref(assertion));
	return 0;
}

/**
 * lasso_data_service_init_query
 * @service: a #LassoDataService
 * @select: resource selection string (typically a XPath query)
 * @item_id: query item identifier (optional)
 *
 * Initializes a new dst:Query request, asking for element @select (with
 * optional itemID set to @item_id).  @item_id may be NULL only if the query
 * won't contain other query items.
 *
 * If both @select and @item_id are NULL, only a skeleton request is created
 * and calls to lasso_data_service_add_query_item() will need to be done.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_init_query(LassoDataService *service, const char *select,
	const char *item_id, const char *security_mech_id)
{
	LassoWsfProfile *profile;
	LassoDstQuery *query;
	LassoDiscoResourceOffering *offering;
	LassoDiscoDescription *description;
	GList *iter;

	profile = LASSO_WSF_PROFILE(service);

	if (select) {
		query = lasso_dst_query_new(lasso_dst_query_item_new(select, item_id));
	} else {
		query = lasso_dst_query_new(NULL);
	}
	profile->request = LASSO_NODE(query);

	if (service == NULL || service->private_data == NULL
			|| service->private_data->offering == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING;
	}
	offering = service->private_data->offering;

	if (offering->ServiceInstance == NULL
			|| offering->ServiceInstance->ServiceType == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE;
	}
	query->hrefServiceType = g_strdup(offering->ServiceInstance->ServiceType);
	query->prefixServiceType = lasso_get_prefix_for_dst_service_href(
		query->hrefServiceType);
	if (query->prefixServiceType == NULL) {
		return LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST;
	}

	if (offering->ResourceID) {
		query->ResourceID = g_object_ref(offering->ResourceID);
	} else if (offering->EncryptedResourceID) {
		query->EncryptedResourceID = g_object_ref(offering->EncryptedResourceID);
	} else {
		/* XXX: no resource id, implied:resource, etc. */
		return LASSO_ERROR_UNIMPLEMENTED;
	}

	lasso_wsf_profile_init_soap_request(LASSO_WSF_PROFILE(service), LASSO_NODE(query));

	/* Set description */
	if (security_mech_id == NULL) {
		description = LASSO_DISCO_DESCRIPTION(offering->ServiceInstance->Description->data);
	} else {
		description = lasso_discovery_get_description_auto(offering, security_mech_id);
	}
	if (description == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION;
	}
	lasso_wsf_profile_set_description(LASSO_WSF_PROFILE(service), description);

	/* Set msgUrl */
	if (description->Endpoint != NULL) {
		profile->msg_url = g_strdup(description->Endpoint);
	} else {
		/* XXX: else, description->WsdlURLI, get endpoint automatically */
		return LASSO_ERROR_UNIMPLEMENTED;
	}

	/* Added needed credential for remote service */
	if (description->CredentialRef) {
		char *credentialRef = description->CredentialRef->data;
		iter = service->private_data->credentials;
		while (iter) {
			LassoSamlAssertion *credential = LASSO_SAML_ASSERTION(iter->data);
			if (strcmp(credentialRef, credential->AssertionID) == 0) {
				/* lasso_wsf_profile_add_saml_authentication(
					LASSO_WSF_PROFILE(service), credential); */
				iter = iter->next;
			}
		}
	}

	return 0;
}

/**
 * lasso_data_service_add_query_item:
 * @service: a #LassoDataService
 * @select: resource selection string (typically a XPath query)
 * @item_id: query item identifier
 *
 * Adds a dst:QueryItem to the current dst:Query request.
 *
 * Return value: a newly created #LassoDstQueryItem with the query item that
 *       has been created.  Note that it is internally allocated and shouldn't
 *       be freed by the caller.
 **/
LassoDstQueryItem*
lasso_data_service_add_query_item(LassoDataService *service,
		const char *select, const char *item_id)
{
	LassoDstQuery *query;
	LassoDstQueryItem *item;

	g_return_val_if_fail(LASSO_IS_DATA_SERVICE(service), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	if (! LASSO_IS_DST_QUERY(LASSO_WSF_PROFILE(service)->request)) {
		return NULL;
	}

	query = LASSO_DST_QUERY(LASSO_WSF_PROFILE(service)->request);

	if (query->QueryItem && query->QueryItem->data &&
			LASSO_DST_QUERY_ITEM(query->QueryItem->data)->itemID == NULL) {
		/* XXX: all items must have itemID if there is more than one,
		 * perhaps we could generate an item id for those lacking it */
		return NULL;
	}

	item = lasso_dst_query_item_new(select, item_id);
	query->QueryItem = g_list_append(query->QueryItem, item);

	return item;
}

/**
 * lasso_data_service_process_query_msg:
 * @service: a #LassoDataService
 * @message: the dst query message
 *
 * Processes a dst:Query message.  Rebuilds a request object from the message
 * and extracts ResourceID.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_process_query_msg(LassoDataService *service, const char *message,
	const char *security_mech_id)
{
	LassoDstQuery *query;
	LassoWsfProfile *profile;
	int rc;
	gchar *service_type;
	GList *node_list;
	LassoSoapEnvelope *envelope;
	xmlDoc *doc;
	xmlNode *xmlnode;

	/* FIXME: another way to get the service type ? */

	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	doc = lasso_xml_parse_memory(message, strlen(message));
	if (doc == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	xmlnode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature,
			xmlSecDSigNs);
	if (xmlnode) {
		xmlUnlinkNode(xmlnode);
		xmlFreeNode(xmlnode);
		xmlnode = NULL;
	}

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	if (envelope->Body == NULL || envelope->Body->any == NULL
			|| envelope->Body->any->data == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}
	query = LASSO_DST_QUERY(envelope->Body->any->data);
	service_type = g_strdup(query->hrefServiceType);
	lasso_release_doc(doc);

	profile = LASSO_WSF_PROFILE(service);
	rc = lasso_wsf_profile_process_soap_request_msg(profile, message, service_type,
							security_mech_id);
	if (rc) {
		return rc;
	}

	/* get provider id from soap:Header */
	for (node_list = profile->soap_envelope_request->Header->Other;
			node_list; node_list = g_list_next(node_list)) {
		LassoNode *node = node_list->data;
		if (LASSO_IS_SOAP_BINDING_PROVIDER(node)) {
			if (service->provider_id)
				g_free(service->provider_id);
			service->provider_id = g_strdup(
				LASSO_SOAP_BINDING_PROVIDER(node)->providerID);
		}
	}

	if (query->ResourceID) {
		service->resource_id = g_object_ref(query->ResourceID);
	} else if (query->EncryptedResourceID) {
		service->encrypted_resource_id = g_object_ref(query->EncryptedResourceID);
	} else {
		return LASSO_ERROR_UNIMPLEMENTED; /* implied ? */
	}

	return 0;
}

/**
 * lasso_data_service_build_response_msg:
 * @service: a #LassoDataService
 *
 * Builds a dst:QueryResponse message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_build_response_msg(LassoDataService *service)
{
	LassoWsfProfile *profile;
	LassoDstQuery *request;
	LassoDstQueryResponse *response;
	GList *iter;
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	LassoSoapEnvelope *envelope;

	profile = LASSO_WSF_PROFILE(service);
	request = LASSO_DST_QUERY(profile->request);

	envelope = profile->soap_envelope_response;

	if (service->private_data->fault != NULL) {
		envelope->Body->any = g_list_append(
			envelope->Body->any, service->private_data->fault);
		return lasso_wsf_profile_build_soap_response_msg(profile);
	}

	response = lasso_dst_query_response_new(
		lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK));
	profile->response = LASSO_NODE(response);
	response->prefixServiceType = g_strdup(request->prefixServiceType);
	response->hrefServiceType = g_strdup(request->hrefServiceType);
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, service->resource_data);
	xpathCtx = xmlXPathNewContext(doc);
	lasso_register_idwsf_xpath_namespaces(xpathCtx);

	/* XXX: needs another level, since there may be more than one <dst:Query> */
	iter = request->QueryItem;
	while (iter) {
		LassoDstQueryItem *item = iter->data;
		LassoDstData *data;

		xpathObj = xmlXPathEvalExpression((xmlChar*)item->Select, xpathCtx);
		if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
			xmlNode *node = xpathObj->nodesetval->nodeTab[0];
			/* XXX: assuming there is only one matching node */
			data = lasso_dst_data_new();
			data->any = g_list_append(data->any, xmlCopyNode(node, 1));
		} else if (xpathObj && xpathObj->type == XPATH_STRING) {
			data = lasso_dst_data_new();
			data->any = g_list_append(data->any,
					xmlNewText(xpathObj->stringval));
		} else {
			/* no response was found, break here */
			if (xpathObj) {
				xmlXPathFreeObject(xpathObj);
			}
			break;
		}
		if (item->itemID) {
			data->itemIDRef = g_strdup(item->itemID);
		}
		response->Data = g_list_append(response->Data, data);
		xmlXPathFreeObject(xpathObj);
		xpathObj = NULL;
		iter = g_list_next(iter);
	}

	xmlUnlinkNode(service->resource_data);
	xmlXPathFreeContext(xpathCtx);
	lasso_release_doc(doc);

	return lasso_wsf_profile_build_soap_response_msg(profile);
}

/**
 * lasso_data_service_get_answer:
 * @service: a #LassoDataService
 * @select: resource selection string (typically a XPath query)
 *
 * Returns the answer for the specified @select request.
 *
 * Return value: the node (libxml2 xmlNode*); or NULL if it was not found.
 *      This xmlnode must be freed by caller.
 **/
xmlNode*
lasso_data_service_get_answer(LassoDataService *service, const char *select)
{
	LassoDstQueryResponse *response;
	LassoDstData *data = NULL;
	GList *iter;
	char *item_id = NULL;

	response = LASSO_DST_QUERY_RESPONSE(LASSO_WSF_PROFILE(service)->response);
	iter = LASSO_DST_QUERY(LASSO_WSF_PROFILE(service)->request)->QueryItem;

	if (select == NULL) {
		/* if only one element; default to first */
		if (g_list_length(iter) > 1)
			return NULL;
		if (response->Data == NULL)
			return NULL;
		data = response->Data->data;
	} else {
		LassoDstQueryItem *item = NULL;
		/* lookup select in query to get itemId, then get data with itemIdRef */
		/* XXX: needs another level, since there may be more than one dst:Query */
		while (iter) {
			item = iter->data;
			iter = g_list_next(iter);
			if (strcmp(item->Select, select) == 0) {
				break;
			}
			item = NULL;
		}

		iter = LASSO_DST_QUERY(LASSO_WSF_PROFILE(service)->request)->QueryItem;
		if (item == NULL) {
			/* not found */
			return NULL;
		}
		item_id = item->itemID;
		if (item_id == NULL) {
			/* item_id is not mandatory when there is only one item */
			if (response->Data == NULL)
				return NULL;
			data = response->Data->data;
		}

		iter = response->Data;
		while (iter && item_id) {
			LassoDstData *t = iter->data;
			iter = g_list_next(iter);
			if (strcmp(t->itemIDRef, item_id) == 0) {
				data = t;
				break;
			}
		}
		if (data == NULL) {
			/* not found */
			return NULL;
		}
	}

	/* XXX: there may be more than one xmlnode */
	return xmlCopyNode(data->any->data, 1);
}

/**
 * lasso_data_service_get_answer_for_item_id:
 * @service: a #LassoDataService
 * @item_id: query item identifier
 *
 * Returns the answer for the specified @item_id query item.
 *
 * Return value: the node (libxml2 xmlNode*); or NULL if it was not found.
 *      This xmlnode must be freed by caller.
 **/
xmlNode*
lasso_data_service_get_answer_for_item_id(LassoDataService *service, const char *item_id)
{
	LassoDstQueryResponse *response;
	LassoDstData *data = NULL;
	GList *iter;

	response = LASSO_DST_QUERY_RESPONSE(LASSO_WSF_PROFILE(service)->response);

	iter = response->Data;
	while (iter && item_id) {
		LassoDstData *t = iter->data;
		iter = g_list_next(iter);
		if (strcmp(t->itemIDRef, item_id) == 0) {
			data = t;
			break;
		}
	}
	if (data == NULL) {
		/* not found */
		return NULL;
	}

	/* XXX: there may be more than one xmlnode */
	return xmlCopyNode(data->any->data, 1);
}


/**
 * lasso_data_service_process_query_response_msg:
 * @service: a #LassoDataService
 * @message: the dst query response message
 *
 * Processes a dst:Query message.  Rebuilds a request object from the message
 * and extracts ResourcedID.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_process_query_response_msg(LassoDataService *service,
	const char *message)
{
	int rc;
	LassoSoapFault *fault = NULL;
	LassoIsRedirectRequest *redirect_request = NULL;
	GList *iter;

	rc = lasso_wsf_profile_process_soap_response_msg(LASSO_WSF_PROFILE(service), message);
	if (rc) return rc;

	/* Process Soap Faults response */
	iter = LASSO_WSF_PROFILE(service)->soap_envelope_response->Body->any;
	while (iter) {
		if (LASSO_IS_SOAP_FAULT(iter->data) == TRUE) {
			fault = LASSO_SOAP_FAULT(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (!fault)
		return 0;

	iter = fault->Detail->any;
	while (iter) {
		if (LASSO_IS_IS_REDIRECT_REQUEST(iter->data) == TRUE) {
			redirect_request = LASSO_IS_REDIRECT_REQUEST(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (redirect_request)
		return LASSO_SOAP_FAULT_REDIRECT_REQUEST;

	return 0;
}

gint
lasso_data_service_need_redirect_user(LassoDataService *service, const char *redirectUrl)
{
	LassoSoapDetail *detail;

	/* Find a SOAP fault element */
	service->private_data->fault = lasso_soap_fault_new();
	service->private_data->fault->faultcode = g_strdup(LASSO_SOAP_FAULT_CODE_SERVER);
	detail = lasso_soap_detail_new();
	detail->any = g_list_append(detail->any, lasso_is_redirect_request_new(redirectUrl));
	service->private_data->fault->Detail = detail;

	return 0;
}

/**
 * lasso_data_service_get_redirect_request_url:
 * @service: a #LassoDataService
 * @message: the dst query message
 *
 * Tells if Attribute Provider needs user interaction.
 *
 * Return value: TRUE if needed; or FALSE otherwise.
 **/
gchar*
lasso_data_service_get_redirect_request_url(LassoDataService *service)
{
	LassoSoapFault *fault = NULL;
	LassoIsRedirectRequest *redirect_request = NULL;
	GList *iter;

	if (LASSO_WSF_PROFILE(service)->soap_envelope_response == NULL ||
			LASSO_WSF_PROFILE(service)->soap_envelope_response->Body == NULL) {
		return NULL;
	}

	iter = LASSO_WSF_PROFILE(service)->soap_envelope_response->Body->any;
	while (iter) {
		if (LASSO_IS_SOAP_FAULT(iter->data) == TRUE) {
			fault = LASSO_SOAP_FAULT(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (fault == NULL || fault->Detail == NULL)
		return NULL;

	iter = fault->Detail->any;
	while (iter) {
		if (LASSO_IS_IS_REDIRECT_REQUEST(iter->data) == TRUE) {
			redirect_request = LASSO_IS_REDIRECT_REQUEST(iter->data);
			break;
		}
		iter = g_list_next(iter);
	}
	if (redirect_request == NULL)
		return NULL;

	return g_strdup(redirect_request->redirectURL);
}

gint
lasso_data_service_init_modify(LassoDataService *service, const gchar *select,
	xmlNode *xmlData)
{
	LassoDstModification *modification;
	LassoDstNewData *newData;
	LassoDiscoResourceOffering *offering;
	LassoDiscoDescription *description = NULL;
	LassoWsfProfile *profile;
	LassoDstModify *modify;

	g_return_val_if_fail(LASSO_IS_DATA_SERVICE(service),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(service != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(xmlData != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_WSF_PROFILE(service);

	/* init Modify */
	modification = lasso_dst_modification_new(select);
	newData = lasso_dst_new_data_new();
	newData->any = g_list_append(newData->any, xmlCopyNode(xmlData, 1));
	modification->NewData = newData;

	modify = lasso_dst_modify_new(modification);
	profile->request = LASSO_NODE(modify);

	if (service == NULL || service->private_data == NULL
			|| service->private_data->offering == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING;
	}
	offering = service->private_data->offering;

	if (offering->ServiceInstance == NULL
			|| offering->ServiceInstance->ServiceType == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE;
	}
	modify->hrefServiceType = g_strdup(offering->ServiceInstance->ServiceType);
	modify->prefixServiceType = lasso_get_prefix_for_dst_service_href(
			modify->hrefServiceType);
	if (modify->prefixServiceType == NULL) {
		return LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST;
	}

	/* get ResourceID / EncryptedResourceID */
	if (offering->ResourceID) {
		modify->ResourceID = offering->ResourceID;
	} else if (offering->EncryptedResourceID) {
		modify->EncryptedResourceID = offering->EncryptedResourceID;
	} else {
		/* XXX: no resource id, implied:resource, etc. */
		return LASSO_ERROR_UNIMPLEMENTED;
	}

	lasso_wsf_profile_init_soap_request(LASSO_WSF_PROFILE(service), LASSO_NODE(modify));

	/* Set description */
	if (offering->ServiceInstance != NULL && offering->ServiceInstance->Description != NULL) {
		description = LASSO_DISCO_DESCRIPTION(offering->ServiceInstance->Description->data);
	}
	if (description == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION;
	}
	lasso_wsf_profile_set_description(LASSO_WSF_PROFILE(service), description);

	/* Set msgUrl */
	if (description->Endpoint != NULL) {
		profile->msg_url = g_strdup(description->Endpoint);
	} else {
		/* XXX: else, description->WsdlURLI, get endpoint automatically */
		return LASSO_ERROR_UNIMPLEMENTED;
	}

	return 0;
}

LassoDstModification*
lasso_data_service_add_modification(LassoDataService *service, const gchar *select)
{
	LassoWsfProfile *profile;
	LassoDstModification *modification;

	g_return_val_if_fail(LASSO_IS_DATA_SERVICE(service), NULL);
	g_return_val_if_fail(select != NULL, NULL);

	profile = LASSO_WSF_PROFILE(service);

	modification = lasso_dst_modification_new(select);
	LASSO_DST_MODIFY(profile->request)->Modification = g_list_append(
		LASSO_DST_MODIFY(profile->request)->Modification, (gpointer)modification);

	return modification;
}

gint
lasso_data_service_build_modify_response_msg(LassoDataService *service)
{
	LassoWsfProfile *profile;
	LassoDstModify *request;
	LassoDstModifyResponse *response;
	LassoSoapEnvelope *envelope;
	GList *iter;
	xmlNode *cur_data;
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	int res = 0;
	GList *node_to_free = NULL;

	profile = LASSO_WSF_PROFILE(service);
	request = LASSO_DST_MODIFY(profile->request);

	if (service->private_data->fault != NULL) {
		envelope = profile->soap_envelope_response;
		envelope->Body->any = g_list_append(
			envelope->Body->any, service->private_data->fault);
		return lasso_wsf_profile_build_soap_response_msg(profile);
	}

	if (service->resource_data == NULL) {
		return LASSO_DST_ERROR_MISSING_SERVICE_DATA;
	} else {
		cur_data = xmlCopyNode(service->resource_data, 1);
	}

	response = lasso_dst_modify_response_new(
		lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK));
	profile->response = LASSO_NODE(response);
	response->prefixServiceType = g_strdup(request->prefixServiceType);
	response->hrefServiceType = g_strdup(request->hrefServiceType);
	envelope = profile->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, cur_data);
	xpathCtx = xmlXPathNewContext(doc);
	lasso_register_idwsf_xpath_namespaces(xpathCtx);

	for (iter = request->Modification; iter != NULL; iter = g_list_next(iter)) {
		LassoDstModification *modification = iter->data;
		xmlNode *newNode = modification->NewData->any->data;
		xpathObj = xmlXPathEvalExpression((xmlChar*)modification->Select,
			xpathCtx);
		if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
			xmlNode *node = xpathObj->nodesetval->nodeTab[0];
			if (node != NULL) {
				/* If we must replace the root element, change it in the xmlDoc */
				if (node == cur_data) {
					xmlDocSetRootElement(doc, xmlCopyNode(newNode,1));
					lasso_list_add(node_to_free, node);
					cur_data = NULL;
				} else {
					xmlReplaceNode(node, xmlCopyNode(newNode,1));
					/* Node is a free node now but is still reference by the xpath nodeset
					   we must wait for the deallocation of the nodeset to free it. */
					lasso_list_add(node_to_free, node);
				}
			}
		} else {
			res = LASSO_DST_ERROR_MODIFY_FAILED;
		}
		xmlXPathFreeObject(xpathObj);
		xpathObj = NULL;
	}

	if (res == 0 && doc->children != NULL) {
		/* Save new service resource data */
		xmlNode *root = xmlDocGetRootElement(doc);
		xmlFreeNode(service->resource_data);
		service->resource_data = xmlCopyNode(root,1);
	}

	xmlXPathFreeContext(xpathCtx);
	g_list_foreach(node_to_free, (GFunc)xmlFreeNode, NULL);
	lasso_release_doc(doc);
	lasso_release_list(node_to_free);

	return lasso_wsf_profile_build_soap_response_msg(profile);
}

gint
lasso_data_service_process_modify_msg(LassoDataService *service,
	const gchar *modify_soap_msg, const gchar *security_mech_id)
{
	LassoDstModify *modify;
	LassoWsfProfile *profile;
	LassoSoapEnvelope *envelope;
	xmlDoc *doc;
	int rc;
	gchar *service_type;


	doc = lasso_xml_parse_memory(modify_soap_msg, strlen(modify_soap_msg));
	if (doc == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	if (envelope->Body == NULL || envelope->Body->any == NULL
			|| envelope->Body->any->data == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	modify = LASSO_DST_MODIFY(envelope->Body->any->data);
	service_type = g_strdup(modify->hrefServiceType);
	lasso_release_doc(doc);

	profile = LASSO_WSF_PROFILE(service);
	rc = lasso_wsf_profile_process_soap_request_msg(profile, modify_soap_msg, service_type,
							security_mech_id);
	if (rc) {
		return rc;
	}

	if (modify->ResourceID) {
		service->resource_id = g_object_ref(modify->ResourceID);
	} else if (modify->EncryptedResourceID) {
		service->encrypted_resource_id = g_object_ref(modify->EncryptedResourceID);
	} else {
		return LASSO_ERROR_UNIMPLEMENTED; /* implied ? */
	}

	return 0;
}

/**
 * lasso_data_service_process_modify_response_msg
 * @service: a #LassoDataService
 * @soap_msg: the SOAP message
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_process_modify_response_msg(LassoDataService *service, const gchar *soap_msg)
{
	LassoDstModifyResponse *response;
	LassoSoapEnvelope *envelope;

	g_return_val_if_fail(LASSO_IS_DATA_SERVICE(service),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(soap_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(soap_msg));
	if (envelope == NULL || ! envelope->Body || ! envelope->Body->any ||
			! LASSO_IS_NODE(envelope->Body->any->data)) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	LASSO_WSF_PROFILE(service)->soap_envelope_response = envelope;
	response = envelope->Body->any->data;
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);

	return 0;
}

/**
 * lasso_data_service_get_resource_offering:
 * @service: a #LassoDataService
 *
 * Gets the #LassoDiscoResourceOffering of the @service.
 *
 * Return value: the #LassoDiscoResourceOffering associated to service.
 **/
LassoDiscoResourceOffering*
lasso_data_service_get_resource_offering(LassoDataService *service)
{
	return g_object_ref(service->private_data->offering);
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

void
lasso_data_service_set_offering(LassoDataService *service, LassoDiscoResourceOffering *offering)
{
	service->private_data->offering = g_object_ref(offering);
	if (offering->ResourceID != NULL) {
		service->resource_id = g_object_ref(offering->ResourceID);
	}
	if (offering->EncryptedResourceID != NULL) {
		service->encrypted_resource_id = g_object_ref(offering->EncryptedResourceID);
	}
	service->provider_id = g_strdup(offering->ServiceInstance->ProviderID);
	service->abstract_description = g_strdup(offering->Abstract);
}

static void
register_xpath_namespace(gchar *prefix, gchar *href, xmlXPathContext *xpathCtx)
{
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)prefix, (xmlChar*)href);
}

static void
lasso_register_idwsf_xpath_namespaces(xmlXPathContext *xpathCtx)
{
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)LASSO_PP_PREFIX,
			(xmlChar*)LASSO_PP_HREF);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)LASSO_EP_PREFIX,
			(xmlChar*)LASSO_EP_HREF);
	if (dst_services_by_prefix == NULL)
		return;
	g_hash_table_foreach(dst_services_by_prefix,
			(GHFunc)register_xpath_namespace, xpathCtx);
}


/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoDataService *service = LASSO_DATA_SERVICE(object);

	if (service->private_data->dispose_has_run == TRUE)
		return;
	g_free(service->provider_id);
	service->provider_id = NULL;
	service->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoDataService *service = LASSO_DATA_SERVICE(object);
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
instance_init(LassoDataService *service)
{
	service->resource_data = NULL;
	service->private_data = g_new0(LassoDataServicePrivate, 1);
	service->private_data->fault = NULL;
}

static void
class_init(LassoDataServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_data_service_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoDataServiceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDataService),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
				"LassoDataService", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_data_service_new:
 * @server: the #LassoServer
 *
 * Creates a new #LassoDataService.
 *
 * Return value: a newly created #LassoDataService object; or NULL if an
 *      error occured.
 **/
LassoDataService*
lasso_data_service_new(LassoServer *server)
{
	LassoDataService *service;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	service = g_object_new(LASSO_TYPE_DATA_SERVICE, NULL);
	LASSO_WSF_PROFILE(service)->server = g_object_ref(server);

	return service;
}

LassoDataService*
lasso_data_service_new_full(LassoServer *server, LassoDiscoResourceOffering *offering)
{
	LassoDataService *service = lasso_data_service_new(server);

	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(offering), NULL);

	if (service == NULL) {
		return NULL;
	}

	lasso_data_service_set_offering(LASSO_DATA_SERVICE(service), offering);

	return service;
}
