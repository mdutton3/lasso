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
 * @short_description: ID-WSF Data Service profile
 *
 * DataService allows Attribute Consumers (WSC) to request an Attribute Provider (WSP) to get
 * or modify data about users with their consent.
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

#include "../xml/private.h"
#include "../utils.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <lasso/id-wsf/discovery.h>
#include <lasso/id-wsf/data_service.h>
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
#include "./wsf_profile_private.h"

extern GHashTable *dst_services_by_prefix; /* cf xml/xml.c */

static void lasso_register_idwsf_xpath_namespaces(xmlXPathContext *xpathCtx);
static gint lasso_data_service_apply_query(LassoDataService *service,
		LassoDstQueryResponse *query_response, xmlXPathContext *xpathCtx,
		LassoDstQueryItem *item);
G_GNUC_UNUSED static gint lasso_data_service_apply_queries(LassoDataService *service,
		LassoDstQueryResponse *query_response, xmlNode *data, GList *queries);


struct _LassoDataServicePrivate {
	xmlNode *resource_data;
	LassoDiscoResourceID *ResourceID;
	LassoDiscoResourceID *EncryptedResourceID;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_data_service_init_query
 * @service: a #LassoDataService
 * @select: resource selection string (typically a XPath query)
 * @item_id: query item identifier (optional)
 *
 * Initializes a new dst:Query request, asking for element @select (with optional itemID set to
 * @item_id).  @item_id may be NULL only if the query won't contain other query items. You must
 * follow this constraint, it will not be checked.
 *
 * If both @select and @item_id are NULL, only a skeleton request is created and calls to
 * lasso_data_service_add_query_item() will need to be done.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_init_query(LassoDataService *service, const char *select,
	const char *item_id, G_GNUC_UNUSED const char *security_mech_id)
{
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstQuery *query = NULL;
	LassoDiscoResourceOffering *offering = NULL;
	gint rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	wsf_profile = &service->parent;

	/* 1. build the message content */
	if (select) {
		query = lasso_dst_query_new(lasso_dst_query_item_new(select, item_id));
	} else {
		query = lasso_dst_query_new(NULL);
	}
	lasso_assign_string(query->hrefServiceType, offering->ServiceInstance->ServiceType);
	lasso_assign_new_string(query->prefixServiceType, lasso_get_prefix_for_dst_service_href(
				query->hrefServiceType));
	goto_cleanup_if_fail_with_rc (query->prefixServiceType != NULL,
			LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST);

	/* 2. build the envelope */
	rc = lasso_wsf_profile_init_soap_request(wsf_profile, &query->parent);

cleanup:
	lasso_release_gobject(query);
	return rc;
}

/**
 * lasso_data_service_add_query_item:
 * @service: a #LassoDataService
 * @select: resource selection string (typically a XPath query)
 * @item_id: query item identifier
 *
 * Adds a dst:QueryItem to the current dst:Query request. If there are already query item in the
 * request and @itemId is NULL, the call will fail.
 *
 * Return value: 0 if sucessfull, an error code otherwise.
 **/
gint
lasso_data_service_add_query_item(LassoDataService *service,
		const char *select, const char *item_id)
{
	LassoWsfProfile *wsf_profile;
	LassoDstQuery *query = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	wsf_profile = &service->parent;

	lasso_return_val_if_invalid_param(DST_QUERY, wsf_profile->request,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);
	query = (LassoDstQuery*)wsf_profile->request;

	/** Check that we can add a new item */
	if (query->QueryItem && (
		(query->QueryItem->data &&
		 (! LASSO_IS_DST_QUERY_ITEM(query->QueryItem->data) ||
		  LASSO_DST_QUERY_ITEM(query->QueryItem->data)->itemID == NULL)) ||
		(item_id == NULL))) {
		return LASSO_DATA_SERVICE_CANNOT_ADD_ITEM;
	}

	lasso_list_add_new_gobject(query->QueryItem, lasso_dst_query_item_new(select, item_id));

	return rc;
}

/**
 * lasso_data_service_get_query_item:
 * @service: a #LassoDataService
 * @select: the select string of the query item to found
 * @item_id: the item id of the query item to found
 * @output: a #LassoDstQueryItem handle to store the result object, its reference count is not
 * incremented.
 *
 * Look up the first query item in the current request matching the given criteria, @select or
 * @item_id. At least one of the criteria must be present for the call to succeed.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_data_service_get_query_item(LassoDataService *service,
		const char *select, const char *item_id, LassoDstQueryItem **output)
{
	LassoDstQuery *query = NULL;
	GList *query_items = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	gint rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	g_return_val_if_fail(select || item_id, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(query, wsf_profile->request, DST_QUERY, LASSO_PROFILE_ERROR_MISSING_REQUEST);
	lasso_foreach(query_items, query->QueryItem)
	{
		LassoDstQueryItem *query_item = NULL;
		lasso_extract_node_or_fail(query_item, query_items->data, DST_QUERY_ITEM, LASSO_ERROR_CAST_FAILED);
		if ((select && g_strcmp0(select, query_item->Select)) ||
			(item_id && g_strcmp0(item_id, query_item->itemID)))
		{
			if (output) {
				lasso_assign_new_gobject(*output, query_item);
			}
		}
	}

cleanup:
	return rc;
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
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstQuery *query = NULL;
	LassoDstQueryResponse *query_response = NULL;
	gchar *service_type = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(message);
	wsf_profile = &service->parent;

	rc = lasso_wsf_profile_process_soap_request_msg(wsf_profile, message, security_mech_id);
	goto_cleanup_if_fail(! rc);

	lasso_return_val_if_invalid_param(DST_QUERY, wsf_profile->request,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	query = (LassoDstQuery*)wsf_profile->request;
	lasso_assign_string(service_type, query->hrefServiceType);

	lasso_wsf_profile_helper_assign_resource_id(service->private_data, query);
	query_response = lasso_dst_query_response_new(NULL);
	/* FIXME: initialize the response object */
	rc = lasso_wsf_profile_init_soap_response(wsf_profile, LASSO_NODE(query_response));
cleanup:
	lasso_release_gobject(query_response);
	return rc;
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
lasso_data_service_build_query_response_msg(LassoDataService *service)
{
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstQuery *request = NULL;
	LassoDstQueryResponse *response = NULL;
	LassoSoapEnvelope *envelope = NULL;
	gint rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(request, wsf_profile->request, DST_QUERY, LASSO_PROFILE_ERROR_MISSING_REQUEST);

	envelope = wsf_profile->soap_envelope_response;

	response = lasso_dst_query_response_new(
		lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK));
	wsf_profile->response = LASSO_NODE(response);
	response->prefixServiceType = g_strdup(request->prefixServiceType);
	response->hrefServiceType = g_strdup(request->hrefServiceType);
	envelope->Body->any = g_list_append(envelope->Body->any, response);


	return lasso_wsf_profile_build_soap_response_msg(wsf_profile);
cleanup:
	return rc;
}

/**
 * lasso_data_service_get_answers:
 * @service: a #LassoDataService object.
 * @output: an xmlNode** pointer where to put the xmlNode* of the result
 *
 * Get all the xmlNode content of the first Data element of the QueryResponse message.
 *
 * Return value: 0 if sucessful, an error code otherwise.
 */
gint
lasso_data_service_get_answers(LassoDataService *service, GList **output)
{
	LassoDstQueryResponse *query_response = NULL;
	LassoDstData *data = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	GList *datas = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(query_response, wsf_profile->request, DST_QUERY_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	datas = query_response->Data;

	if (datas) {
		lasso_extract_node_or_fail(data, datas->data, DST_DATA,
				LASSO_ERROR_CAST_FAILED);
	}

	if (data) {
		if (output) {
			GList *data_content = data->any;
			lasso_release_list_of_xml_node(*output);
			for (;data_content; data_content = g_list_next(data_content)) {
				lasso_list_add_xml_node(*output, data_content->data);
			}
		}
	} else {
		rc = LASSO_DST_ERROR_NO_DATA;
	}

cleanup:
	return rc;
}
/**
 * lasso_data_service_get_answer:
 * @service: a #LassoDataService object.
 * @output: an xmlNode** pointer where to put the xmlNode* of the result
 *
 * Get the first xmlNode of the first Data element of the QueryResponse message.
 *
 * Return value: 0 if sucessful, an error code otherwise.
 */
gint
lasso_data_service_get_answer(LassoDataService *service, xmlNode **output)
{
	LassoDstQueryResponse *query_response = NULL;
	LassoDstData *data = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	GList *datas = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(query_response, wsf_profile->request, DST_QUERY_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	datas = query_response->Data;

	if (datas) {
		lasso_extract_node_or_fail(data, datas->data, DST_DATA,
				LASSO_ERROR_CAST_FAILED);
	}

	if (data) {
		if (output) {
			xmlNode *first_element = NULL;
			if (data->any) {
				first_element = data->any->data;
			}
			lasso_assign_xml_node(*output, first_element);
		}
	} else {
		rc = LASSO_DST_ERROR_NO_DATA;
	}

cleanup:
	return rc;
}

/**
 * lasso_data_service_get_answers_by_select:
 * @service: a #LassoDataService
 * @select: resource selection string (typically a XPath query)
 * @output: a GList** to store a GList* containing the result, it must be freed.
 *
 * Returns the answers for the specified @select request.
 *
 * Return value: 0 if successful, an error code otheriwse
 *
 **/
gint
lasso_data_service_get_answers_by_select(LassoDataService *service, const char *select, GList **output)
{
	LassoDstQuery *query = NULL;
	LassoDstQueryResponse *query_response = NULL;
	LassoDstData *data = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstQueryItem *query_item = NULL;
	GList *iter = NULL;
	GList *datas = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(select);
	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(query, wsf_profile->request, DST_QUERY,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);
	lasso_extract_node_or_fail(query_response, wsf_profile->request, DST_QUERY_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	iter = query->QueryItem;
	datas = query_response->Data;

	/* one query, no need for itemID, data is the first one, or absent */
	if (iter && iter->next == NULL) {
		lasso_extract_node_or_fail(query_item, iter->data, DST_QUERY_ITEM,
				LASSO_ERROR_CAST_FAILED);

		if (datas) {
			lasso_extract_node_or_fail(data, datas->data, DST_DATA,
					LASSO_ERROR_CAST_FAILED);
			if (g_strcmp0(select, query_item->Select) != 0) {
				data = NULL;
				rc = LASSO_DST_ERROR_QUERY_NOT_FOUND;
			}
		} else {
			rc = LASSO_DST_ERROR_NO_DATA;
		}
	/* many queries */
	} else {
		/* lookup select in query to get itemId, then get data with itemIdRef */
		while (iter) {
			lasso_extract_node_or_fail(query_item, iter->data, DST_QUERY_ITEM,
					LASSO_ERROR_CAST_FAILED);
			if (g_strcmp0(query_item->Select, select) == 0) {
				break;
			}
			query_item = NULL;
			iter = g_list_next(iter);
		}
		if (query_item && ! query_item->itemID) {
			goto_cleanup_with_rc(LASSO_DST_ERROR_MALFORMED_QUERY);
		}

		while (datas) {
			lasso_extract_node_or_fail(data, datas->data, DST_DATA,
					LASSO_ERROR_CAST_FAILED);
			if (g_strcmp0(data->itemIDRef, query_item->itemID) == 0) {
				break;
			}
			data = NULL;
			datas = g_list_next(datas);
		}
	}

	if (data) {
		if (output) {
			GList *data_content = data->any;
			lasso_release_list_of_xml_node(*output);
			for (;data_content; data_content = g_list_next(data_content)) {
				lasso_list_add_xml_node(*output, data_content->data);
			}
		}
	} else {
		rc = LASSO_DST_ERROR_NO_DATA;
	}

cleanup:
	return rc;
}

/**
 * lasso_data_service_get_answer_for_item_id:
 * @service: a #LassoDataService
 * @item_id: query item identifier
 * @output: a GList** to store a GList* containing the result, it must be freed.
 *
 * Returns the answers for the specified @itemID request.
 *
 * Return value: 0 if successful, an error code otherwise
 *
 **/
gint
lasso_data_service_get_answers_by_item_id(LassoDataService *service, const char *item_id, GList **output)
{
	LassoDstQueryResponse *query_response = NULL;
	LassoDstData *data = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	GList *datas = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(select);
	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(query_response, wsf_profile->request, DST_QUERY_RESPONSE,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	datas = query_response->Data;
	while (datas) {
		lasso_extract_node_or_fail(data, datas->data, DST_DATA, LASSO_ERROR_CAST_FAILED);
		if (g_strcmp0(data->itemIDRef, item_id) == 0) {
			break;
		}
		data = NULL;
		datas = g_list_next(datas);
	}

	if (data) {
		if (output) {
			GList *data_content = data->any;
			lasso_release_list_of_xml_node(*output);
			for (;data_content; data_content = g_list_next(data_content)) {
				lasso_list_add_xml_node(*output, data_content->data);
			}
		}
	} else {
		rc = LASSO_DST_ERROR_NO_DATA;
	}

cleanup:
	return rc;
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
	int rc = 0;

	rc = lasso_wsf_profile_process_soap_response_msg(LASSO_WSF_PROFILE(service), message);
	if (! rc && ! LASSO_IS_DST_QUERY_RESPONSE(service->parent.response)) {
		rc = LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}

	return rc;
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

/**
 * lasso_data_service_init_modify:
 * @service: a #LassoDataService object
 * @select: an Select command (usually using the XPath syntax)
 * @xmlData: the XML data for replacing the data
 *
 * Initialize a Data Service Template Modify request using a command to select some data, and an XML
 * fragment to replace the selected data.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_data_service_init_modify(LassoDataService *service)
{
	LassoDiscoResourceOffering *offering = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstModify *modify = NULL;
	gint rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(service);

	wsf_profile = &service->parent;
	/* Build the Modify request */
	modify = lasso_dst_modify_new(NULL);

	offering = lasso_wsf_profile_get_resource_offering(wsf_profile);
	goto_cleanup_if_fail_with_rc (offering, LASSO_PROFILE_ERROR_MISSING_RESOURCE_OFFERING);
	goto_cleanup_if_fail_with_rc (offering->ServiceInstance != NULL &&
			offering->ServiceInstance->ServiceType != NULL,
			LASSO_PROFILE_ERROR_MISSING_SERVICE_TYPE);
	lasso_assign_string(modify->hrefServiceType, offering->ServiceInstance->ServiceType);
	lasso_assign_new_string(modify->prefixServiceType, lasso_get_prefix_for_dst_service_href(
				modify->hrefServiceType));
	goto_cleanup_if_fail_with_rc (modify->prefixServiceType != NULL, LASSO_DATA_SERVICE_ERROR_UNREGISTERED_DST);
	lasso_wsf_profile_helper_assign_resource_id(modify, offering);

	rc = lasso_wsf_profile_init_soap_request(wsf_profile, &modify->parent);
cleanup:
	lasso_release_gobject(modify);
	return rc;
}

/**
 * lasso_data_service_add_modification:
 * @service: a #LassoDataService object
 * @select: a selector string
 * @xmlData: optional NewData content
 * @overrideAllowed: wheter to permit delete or replace of existings
 * @notChagendSince: if not NULL, give the time (as a local time_t value) of the last known
 * modification to the datas, it is used to permit secure concurrent accesses.
 *
 * Add a new modification to the current modify request. If overrideAllowed is FALSE, xmlData must
 * absolutely be present. Refer to the ID-WSF DST 1.0 specification for the semantic of the created
 * message.
 *
 * Return value: 0 if successful and the new modification object in *output, an error code
 * otherwise.
 */
gint
lasso_data_service_add_modification(LassoDataService *service, const gchar *select,
		xmlNode *xmlData, gboolean overrideAllowed, time_t *notChangedSince,
		LassoDstModification **output)
{
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstModification *modification = NULL;
	LassoDstNewData *newData = NULL;
	LassoDstModify *modify = NULL;
	gint rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(select);

	wsf_profile = &service->parent;
	lasso_extract_node_or_fail(modify, wsf_profile->request, DST_MODIFY,
			LASSO_ERROR_CAST_FAILED);

	modification = lasso_dst_modification_new(select);
	newData = lasso_dst_new_data_new();
	lasso_release_list_of_xml_node(newData->any);
	lasso_list_add_xml_node(newData->any, xmlData);
	lasso_assign_new_gobject(modification->NewData, newData);
	lasso_list_add_new_gobject(modify->Modification,
			modification);
	modification->overrideAllowed = overrideAllowed;
	if (notChangedSince) {
		lasso_assign_new_string(modification->notChangedSince,
				lasso_time_to_iso_8601_gmt(*notChangedSince));
	}

	if (*output) {
		lasso_assign_gobject(*output, modification);
	}

cleanup:
	return rc;
}

static gint
lasso_data_service_apply_modification(G_GNUC_UNUSED LassoDataService *service, G_GNUC_UNUSED LassoDstModification *modification, G_GNUC_UNUSED xmlXPathContext *xpath_ctxt)
{
	gint rc = 0;
	return rc;
}

G_GNUC_UNUSED static gint
lasso_data_service_apply_modifications(LassoDataService *service, GList *modifications, xmlXPathContext *xpath_ctxt)
{
	gint rc = 0;
	GList *i;

	lasso_foreach(i, modifications) {
		LassoDstModification *dst_modification;

		if (LASSO_IS_DST_MODIFICATION(i->data)) {
			rc = lasso_data_service_apply_modification(service, dst_modification, xpath_ctxt);
			// First error, stop
			if (rc) {
				break;
			}
		}
	}
	return rc;
}

gint
lasso_data_service_build_modify_response_msg(LassoDataService *service)
{
	LassoWsfProfile *wsf_profile = NULL;
	LassoDstModify *request = NULL;
	LassoDstModifyResponse *response = NULL;
	GList *iter = NULL;
	xmlNode *cur_data = NULL;
	xmlDoc *doc = NULL;
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj = NULL;
	GList *node_to_free = NULL;
	int res = 0;
	xmlNode* resource_data;
	gint rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	wsf_profile = &service->parent;
	g_return_val_if_fail(service->private_data, LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT);
	lasso_extract_node_or_fail(request, wsf_profile->request, DST_MODIFY,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);
	resource_data = service->private_data->resource_data;

	if (resource_data == NULL) {
		return LASSO_DST_ERROR_MISSING_SERVICE_DATA;
	} else {
		cur_data = xmlCopyNode(resource_data, 1);
	}

	/* Build the Response object */
	response = lasso_dst_modify_response_new(
		lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK));
	lasso_assign_string(response->prefixServiceType, request->prefixServiceType);
	lasso_assign_string(response->hrefServiceType, request->hrefServiceType);

	/* Create the XPath workbench */
	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, cur_data);
	xpathCtx = xmlXPathNewContext(doc);
	lasso_register_idwsf_xpath_namespaces(xpathCtx);

	/* Apply modifications */
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
					lasso_list_add_xml_node(node_to_free, node);
					cur_data = NULL;
				} else {
					xmlReplaceNode(node, xmlCopyNode(newNode,1));
					/* Node is a free node now but is still reference by the xpath nodeset
					   we must wait for the deallocation of the nodeset to free it. */
					lasso_list_add_xml_node(node_to_free, node);
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
		lasso_assign_xml_node(service->private_data->resource_data, root);
	}

	rc = lasso_wsf_profile_build_soap_response_msg(wsf_profile);
cleanup:
	xmlXPathFreeContext(xpathCtx);
	g_list_foreach(node_to_free, (GFunc)xmlFreeNode, NULL);
	lasso_release_doc(doc);
	lasso_release_list(node_to_free);
	return rc;
}

/**
 * lasso_data_service_process_modify_msg:
 * @service: a #LassoDataService object
 * @modify_soap_msg: the SOAP request string
 * @security_mech_id: the security mechanism to apply
 *
 * Parse the given request message, and initialize needed structures.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_data_service_process_modify_msg(LassoDataService *service,
	const gchar *modify_soap_msg, const gchar *security_mech_id)
{
	LassoDstModify *modify = NULL;
	LassoDstModifyResponse *modify_response = NULL;
	LassoWsfProfile *wsf_profile = NULL;
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(modify_soap_msg);

	wsf_profile = &service->parent;

	rc = lasso_wsf_profile_process_soap_request_msg(wsf_profile, modify_soap_msg, security_mech_id);
	goto_cleanup_if_fail(! rc);
	goto_cleanup_if_fail_with_rc( ! LASSO_IS_DST_MODIFY(wsf_profile->request),
			LASSO_PROFILE_ERROR_MISSING_RESPONSE);

	modify = (LassoDstModify*)wsf_profile->request;
	lasso_wsf_profile_helper_assign_resource_id(service->private_data, modify);
	modify_response = lasso_dst_modify_response_new(NULL);
	rc = lasso_wsf_profile_init_soap_response(wsf_profile, LASSO_NODE(modify_response));
cleanup:
	lasso_release_gobject(modify_response);
	return rc;
}

/**
 * lasso_data_service_process_modify_response_msg
 * @service: a #LassoDataService
 * @soap_msg: the SOAP message
 *
 * Process a modify response message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_data_service_process_modify_response_msg(LassoDataService *service, const gchar *soap_msg)
{
	int rc = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_null_param(soap_msg);

	rc = lasso_wsf_profile_process_soap_response_msg(&service->parent, soap_msg);

	if (! LASSO_IS_DST_MODIFY_RESPONSE(service->parent.response)) {
		rc = LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}

	return rc;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

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

static gint
lasso_data_service_apply_query(LassoDataService *service, LassoDstQueryResponse *query_response, xmlXPathContext *xpathCtx, LassoDstQueryItem *item)
{
	gint rc = 0;
	xmlXPathObject *xpathObj = NULL;
	gint xpath_error_code = 0;

	lasso_bad_param(DATA_SERVICE, service);
	lasso_bad_param(DST_QUERY_RESPONSE, query_response);
	lasso_bad_param(DST_QUERY_ITEM, item);

	if (! item->Select) {
		lasso_wsf_profile_helper_set_status(query_response, LASSO_DST_STATUS_CODE_FAILED);
		lasso_wsf_profile_helper_set_status(query_response->Status, LASSO_DST_STATUS_CODE_MISSING_SELECT);
		goto_cleanup_with_rc(1);
	}

	if (lasso_eval_xpath_expression(xpathCtx, item->Select, &xpathObj, &xpath_error_code)) {
		LassoDstData *data = NULL;

		/* Found zero or more node answers */
		if (xpathObj && xpathObj->type == XPATH_NODESET){
			int i = 0;

			if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
				data = lasso_dst_data_new();
			}

			for (i = 0; xpathObj->nodesetval && i < xpathObj->nodesetval->nodeNr;
					i++) {
				lasso_list_add_xml_node(data->any,
						xpathObj->nodesetval->nodeTab[i]);
			}
		/* Found other kind of answers, convert to string */
		} else  {
			xmlChar *str;

			data = lasso_dst_data_new();
			str = xmlXPathCastToString(xpathObj);
			lasso_list_add_xml_node(data->any, xmlNewText(str));
			lasso_release_xml_string(str);
		}
		if (data) {
			lasso_assign_string(data->itemIDRef, item->itemID);
			lasso_list_add_gobject(query_response->Data, data);
		}
		lasso_release_gobject(data);
	} else {
		char *code = g_strdup_printf("LIBXML_XPATH_ERROR_%d", xpath_error_code);

		lasso_wsf_profile_helper_set_status(query_response, LASSO_DST_STATUS_CODE_FAILED);
		lasso_wsf_profile_helper_set_status(query_response->Status, LASSO_DST_STATUS_CODE_INVALID_SELECT);
		lasso_wsf_profile_helper_set_status(query_response->Status->Status, code);
		lasso_release_string(code);
		goto_cleanup_with_rc(1);
	}

cleanup:
	lasso_release_xpath_object(xpathObj);
	return rc;
}

G_GNUC_UNUSED static gint
lasso_data_service_apply_queries(LassoDataService *service, LassoDstQueryResponse *query_response, xmlNode *data, GList *queries)
{
	gint rc = 0;
	LassoWsfProfile *wsf_profile = NULL;
	xmlDoc *doc = NULL;
	xmlXPathContext *xpathCtx = NULL;

	lasso_bad_param(DATA_SERVICE, service);
	g_return_val_if_fail(service->private_data, LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT);
	wsf_profile = &service->parent;

	/* 1. Check query */
	if (queries && queries->next) {
		GList *q = queries;
		while (q) {
			if (! LASSO_IS_DST_QUERY_ITEM(q->data) || !
					LASSO_DST_QUERY_ITEM(q->data)->itemID) {
				lasso_wsf_profile_helper_set_status(query_response,
						LASSO_DST_STATUS_CODE_FAILED);
				lasso_wsf_profile_helper_set_status(query_response->Status,
						"itemID expected");
				goto_cleanup_with_rc(LASSO_DST_ERROR_QUERY_FAILED);
			}
			q = g_list_next(q);
		}
	}

	/* 1. Setup workbench */
	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, data);
	xpathCtx = xmlXPathNewContext(doc);
	lasso_register_idwsf_xpath_namespaces(xpathCtx);

	lasso_foreach (queries, queries) {
		LassoDstQueryItem *item = queries->data;

		goto_cleanup_if_fail_with_rc(lasso_data_service_apply_query(service, query_response,
					xpathCtx, item) == 0, query_response->Data ?
				LASSO_DST_ERROR_QUERY_PARTIALLY_FAILED :
				LASSO_DST_ERROR_QUERY_FAILED);
	}

cleanup:
	xmlUnlinkNode(service->private_data->resource_data);
	xmlSetTreeDoc(service->private_data->resource_data, NULL);
	lasso_release_xpath_context(xpathCtx);
	lasso_release_doc(doc);

	return rc;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoDataService *service = LASSO_DATA_SERVICE(object);

	lasso_release_xml_node(service->private_data->resource_data);
	lasso_release_gobject(service->private_data->ResourceID);
	lasso_release_gobject(service->private_data->EncryptedResourceID);

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	g_free(((LassoDataService*)object)->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDataService *service)
{
	service->private_data = g_new0(LassoDataServicePrivate, 1);
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

/**
 * lasso_data_service_new_full:
 * @server: the #LassoServer
 * @offering: the #LassoDiscoResourceOffering
 *
 * Creates a new #LassoDataService.
 *
 * Return value: a newly created #LassoDataService object; or NULL if an error occured.
 **/
LassoDataService*
lasso_data_service_new_full(LassoServer *server, LassoDiscoResourceOffering *offering)
{
	LassoDataService *service = lasso_data_service_new(server);

	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(offering), NULL);

	if (service == NULL) {
		return NULL;
	}

	lasso_wsf_profile_set_resource_offering(&service->parent, offering);

	return service;
}
