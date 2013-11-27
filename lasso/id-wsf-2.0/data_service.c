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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * SECTION:idwsf2_data_service
 * @short_description: ID-WSF 2.0 Data Service profile
 *
 * DataService allows Attribute Consumers (WSC) to request an Attribute Provider (WSP) to get
 * or modify data about users with their consent.
 */

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "data_service.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"

#include "../xml/id-wsf-2.0/disco_service_type.h"
#include "../xml/id-wsf-2.0/dstref_query.h"
#include "../xml/id-wsf-2.0/dstref_query_response.h"
#include "../xml/id-wsf-2.0/dstref_data.h"
#include "../xml/id-wsf-2.0/util_status.h"
#include "../xml/id-wsf-2.0/util_response.h"
#include "../xml/id-wsf-2.0/sb2_redirect_request.h"
#include "../xml/id-wsf-2.0/dstref_modify.h"
#include "../xml/id-wsf-2.0/dstref_modify_item.h"
#include "../xml/id-wsf-2.0/dstref_modify_response.h"
#include "../xml/id-wsf-2.0/dstref_create.h"
#include "../xml/id-wsf-2.0/dstref_delete.h"

#include "../xml/soap-1.1/soap_envelope.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/private.h"
#include "../utils.h"
#include "private.h"
#include "idwsf2_helper.h"
#include "soap_binding.h"

struct _LassoIdWsf2DataServicePrivate
{
	gboolean dispose_has_run;
	GList *query_items; /* of LassoIdWsf2DstRefQueryItem */
	GList *query_datas; /* of LassoIdWsf2DstRefData */
	GList *modify_items; /* of LassoIdWsf2DstRefModifyItem */
	gchar *service_type;
	gchar *service_type_prefix;
	GHashTable *namespaces;
};

extern GHashTable *idwsf2_dst_services_by_prefix; /* cf xml/xml.c */

#define lasso_idwsf2_data_service_set_dst_service_type(dst_node, service_type, prefix) \
	lasso_assign_string(dst_node->hrefServiceType, service_type); \
	lasso_assign_string(dst_node->prefixServiceType, prefix); \

static void
lasso_idwsf2_data_service_clean_private_data(LassoIdWsf2DataService *service)
{
	LassoIdWsf2DataServicePrivate *pdata = service->private_data;

	lasso_release_string(pdata->service_type);
	lasso_release_string(pdata->service_type_prefix);
	lasso_release_list_of_gobjects(pdata->query_items);
	lasso_release_list_of_gobjects(pdata->modify_items);
	lasso_release_ghashtable(pdata->namespaces);
}


/**
 * lasso_idwsf2_data_service_set_service_type:
 * @service: a #LassoIdWsf2DataService object
 * @prefix: a prefix to use in producing XML documents
 * @service_type: the service type URI
 *
 * Fix a service type for this @service.
 */
gint
lasso_idwsf2_data_service_set_service_type(LassoIdWsf2DataService *service, const char *prefix,
		const char *service_type)
{
	if (!LASSO_IS_IDWSF2_DATA_SERVICE(service) || lasso_strisempty(prefix)
			|| lasso_strisempty(service_type))
		return LASSO_PARAM_ERROR_INVALID_VALUE;
	lasso_assign_string(service->private_data->service_type_prefix, prefix);
	lasso_assign_string(service->private_data->service_type, service_type);
	return 0;
}

/**
 * lasso_idwsf2_data_service_get_service_type:
 * @service: a #LassoIdWsf2DataService object
 *
 * Return the service type of the received request
 *
 * Return value:(allow-none)(transfer none): the URI of the service type or NULL.
 */
const char*
lasso_idwsf2_data_service_get_service_type(LassoIdWsf2DataService *service)
{
	if (! LASSO_IS_IDWSF2_DATA_SERVICE(service))
		return NULL;
	return service->private_data->service_type;
}

/**
 * lasso_idwsf2_data_service_get_service_type_prefix:
 * @service: a #LassoIdWsf2DataService object
 *
 * Return the service type prefix of the received request
 *
 * Return value:(allow-none)(transfer none): the URI of the service type prefix or NULL.
 */
const char*
lasso_idwsf2_data_service_get_service_type_prefix(LassoIdWsf2DataService *service)
{
	if (! LASSO_IS_IDWSF2_DATA_SERVICE(service))
		return NULL;
	return service->private_data->service_type_prefix;
}

static gint
lasso_idwsf2_data_service_init_request(LassoIdWsf2DataService *service,
		LassoNode *(*constructor)())
{
	int rc = 0;
	LassoNode *request;
	LassoSoapEnvelope *envelope;
	
	lasso_bad_param(IDWSF2_DATA_SERVICE, service);
	lasso_release_list_of_gobjects(service->private_data->query_items);
	lasso_release_list_of_gobjects(service->private_data->modify_items);
	lasso_check_good_rc(lasso_idwsf2_profile_init_request(&service->parent));
	request = (LassoNode*)constructor();
	envelope = lasso_idwsf2_profile_get_soap_envelope_request(&service->parent);
	lasso_assign_new_gobject(service->parent.parent.request, request);
	lasso_soap_envelope_add_to_body(envelope, request);

cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_init_query:
 * @service: a #LassoIdWsf2DataService
 *
 * Initialise an ID-WSF 2.0 DataService query request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_data_service_init_query(LassoIdWsf2DataService *service)
{
	return lasso_idwsf2_data_service_init_request(service,
			(LassoNode *(*)())lasso_idwsf2_dstref_query_new);
}

/**
 * lasso_idwsf2_data_service_init_modify:
 * @service: a #LassoIdWsf2DataService
 *
 * Initialise an ID-WSF 2.0 DataService modify request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_data_service_init_modify(LassoIdWsf2DataService *service)
{
	return lasso_idwsf2_data_service_init_request(service,
			(LassoNode *(*)())lasso_idwsf2_dstref_modify_new);
}

gint
lasso_idwsf2_data_service_init_create(LassoIdWsf2DataService *service)
{
	return lasso_idwsf2_data_service_init_request(service,
			(LassoNode *(*)())lasso_idwsf2_dstref_create_new);
}

gint
lasso_idwsf2_data_service_init_delete(LassoIdWsf2DataService *service)
{
	return lasso_idwsf2_data_service_init_request(service,
			(LassoNode *(*)())lasso_idwsf2_dstref_delete_new);
}

/**
 * lasso_idwsf2_data_service_get_request_type:
 * @service: a #LassoIdWsf2DataService object
 *
 * Return the type of the currently handled request.
 */
LassoIdWsf2DataServiceRequestType
lasso_idwsf2_data_service_get_request_type(LassoIdWsf2DataService *service)
{
	GType request_type = 0;

#define check_request_type(a, b) \
		if (request_type == a) { \
			return b ;\
		}
	if (! LASSO_IS_IDWSF2_DATA_SERVICE(service))
		return LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_UNKNOWN;
	request_type = G_TYPE_FROM_INSTANCE(service->parent.parent.request);
	check_request_type(LASSO_TYPE_IDWSF2_DSTREF_QUERY,
			LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY);
	check_request_type(LASSO_TYPE_IDWSF2_DSTREF_MODIFY,
			LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY);
#undef check_request_type
	return LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_UNKNOWN;
}

/**
 * lasso_idwsf2_data_service_add_query_item:
 * @service: a #LassoIdWsf2DataService
 * @item_query: a query string
 * @item_id:(allow-none): identifier of the queried item, which will allow to retrieve it in the
 * response
 *
 * Add an item in the query request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_data_service_add_query_item(LassoIdWsf2DataService *service, const gchar *item_query,
	const gchar *item_id)
{
	LassoIdWsf2DstRefQueryItem *item;
	GList *i;
	int rc = 0;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);
	lasso_check_non_empty_string(item_query);

	if (item_id == NULL) {
		item_id = lasso_build_unique_id(32);
	}
	/* Check duplicates */
	lasso_foreach(i, service->private_data->query_items) {
		LassoIdWsf2DstRefQueryItem *old_item = (LassoIdWsf2DstRefQueryItem *)i->data;
		if (lasso_strisequal(old_item->parent.parent.itemID,item_id)) {
			return LASSO_IDWSF2_DST_ERROR_DUPLICATE_ITEM;
		}
	}
	item = lasso_idwsf2_dstref_query_item_new_full(item_query, item_id);
	lasso_list_add_gobject(service->private_data->query_items, item);
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_add_modify_item:
 * @service: a #LassoIdWsf2DataService
 * @item_query: XPATH of the item to modify
 * @new_data:(allow-none):new value for the selected item
 * @overrideAllowed:(allow-none)(default FALSE): FALSE means only allowing to create a new item, but
 * not modify existing one, TRUE means allowing to modify existing item
 * @item_id:(allow-none): identifier of the item to modify
 *
 * Add an item in the modification request.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_data_service_add_modify_item(LassoIdWsf2DataService *service, const gchar *item_query,
	xmlNode *new_data, gboolean overrideAllowed, const gchar *item_id)
{
	LassoIdWsf2DstRefModifyItem *item;
	int rc = 0;
	GList *i;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);
	lasso_check_non_empty_string(item_query);

	if (item_id == NULL) {
		item_id = lasso_build_unique_id(10);
	}
	lasso_foreach(i, service->private_data->modify_items) {
		LassoIdWsf2DstRefModifyItem *old_item = (LassoIdWsf2DstRefModifyItem *)i->data;
		if (lasso_strisequal(old_item->id,item_id)) {
			return LASSO_IDWSF2_DST_ERROR_DUPLICATE_ITEM;
		}
	}
	item = lasso_idwsf2_dstref_modify_item_new_full(
		item_query, item_id, new_data, overrideAllowed);
	lasso_list_add_gobject(service->private_data->modify_items, item);

cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_get_item_ids:
 * @service: a #LassoIdWsf2DataService object
 *
 * Return the list of items ids for the currently handled request.
 *
 * Return value:(element-type utf8)(transfer full): a list of string ids, or NULL if none is found.
 * The caller must free the return value.
 */
GList*
lasso_idwsf2_data_service_get_item_ids(LassoIdWsf2DataService *service)
{
	GList *i, *result = NULL;

	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			lasso_foreach(i, service->private_data->query_items) {
				LassoIdWsf2DstRefQueryItem *old_item = (LassoIdWsf2DstRefQueryItem *)i->data;
				lasso_list_add_string(result, old_item->parent.parent.itemID);
			}
			break;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			lasso_foreach(i, service->private_data->modify_items) {
				LassoIdWsf2DstRefModifyItem *old_item = (LassoIdWsf2DstRefModifyItem *)i->data;
				lasso_list_add_string(result, old_item->id);
			}
			break;
		default:
			break;
	}
	return result;
}

/**
 * lasso_idwsf2_data_service_get_items:
 * @service: a #LassoIdWsf2DataService object
 *
 * Return value:(element-type LassoNode)(transfer none): a list of Query or Modify items, or NULL if
 * none is found.
 */
GList*
lasso_idwsf2_data_service_get_items(LassoIdWsf2DataService *service)
{
	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			return service->private_data->query_items;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			return service->private_data->modify_items;
		default:
			break;
	}
	return NULL;
}

/**
 * lasso_idwsf2_data_service_get_item:
 * @service: a #LassoIdWsf2DataService object
 * @item_id: the itemID of the item to return, if NULL try to get the only one item (if there is
 * more than one, it returns NULL).
 *
 * Retrieve a specific item from a request.
 *
 * Return value:(transfer none)(allow-none): a #LassoIdWsf2DstRefQueryItem or a #LassoIdWsf2DstRefModifyItem object, or NULL if
 * no item for the given item_id exists.
 */
LassoNode*
lasso_idwsf2_data_service_get_item(LassoIdWsf2DataService *service,
		const char *item_id)
{
	GList *i;

	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			if (item_id == NULL) {
				if (g_list_length(service->private_data->query_items) == 1)
					return (LassoNode*)service->private_data->query_items->data;
				else
					return NULL;
			}
			lasso_foreach(i, service->private_data->query_items) {
				LassoIdWsf2DstRefQueryItem *old_item = (LassoIdWsf2DstRefQueryItem *)i->data;
				if (lasso_strisequal(old_item->parent.parent.itemID,item_id)) {
					return (LassoNode*)old_item;
				}
			}
			break;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			if (item_id == NULL) {
				if (g_list_length(service->private_data->modify_items) == 1)
					return (LassoNode*)service->private_data->modify_items->data;
				else
					return NULL;
			}
			lasso_foreach(i, service->private_data->modify_items) {
				LassoIdWsf2DstRefModifyItem *old_item = (LassoIdWsf2DstRefModifyItem *)i->data;
				if (lasso_strisequal(old_item->id,item_id)) {
					return (LassoNode*)old_item;
				}
			}
			break;
		default:
			break;
	}
	return NULL;
}

/**
 * lasso_idwsf2_data_service_add_namespace:
 * @service: a #LassoIdWsf2DataService object
 *
 * Add a new namespace to use for example in XPath elements or in Data or NewData objects.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_data_service_add_namespace(LassoIdWsf2DataService *service, const char *prefix,
		const char *href)
{
	if (xmlValidateNCName(BAD_CAST prefix, 0) && ! lasso_strisempty(href))
		return LASSO_PARAM_ERROR_INVALID_VALUE;

	if (g_hash_table_lookup(service->private_data->namespaces, prefix) != NULL ||
			lasso_strisequal(service->private_data->service_type_prefix,prefix) ||
			lasso_strisequal(prefix,LASSO_IDWSF2_DSTREF_PREFIX)) {
		return LASSO_PARAM_ERROR_INVALID_VALUE;
	}

	g_hash_table_insert(service->private_data->namespaces, g_strdup(prefix), g_strdup(href));
	return 0;
}

static void
add_custom_namespace(const char *prefix, const char *href, LassoNode *node)
{
	lasso_node_add_custom_namespace(node, prefix, href);
}

/**
 * lasso_idwsf2_data_service_build_request_msg:
 * @service: a #LassoIdWsf2DataService object
 * @security_mech_id:(allow-none): the security mechanism to employ, default is Bearer mechanism.
 *
 * Build the request message.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_data_service_build_request_msg(LassoIdWsf2DataService *service,
		const char *security_mech_id)
{
	int rc = 0;
	LassoSoapEnvelope *envelope;
	LassoIdWsf2DstRefQuery *query = (LassoIdWsf2DstRefQuery*)service->parent.parent.request;
	LassoIdWsf2DstRefModify *modify = (LassoIdWsf2DstRefModify*)service->parent.parent.request;
	const char *service_type = NULL;
	const char *prefix = NULL;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);

	envelope = lasso_idwsf2_profile_get_soap_envelope_request(&service->parent);
	service_type = lasso_wsa_endpoint_reference_get_idwsf2_service_type(
			lasso_idwsf2_profile_get_epr(&service->parent));
	if (service_type) {
		const char *prefix = lasso_get_prefix_for_idwsf2_dst_service_href(service_type);
		if (! prefix)
			prefix = "dstref";
	} else {
		service_type = service->private_data->service_type;
		prefix = service->private_data->service_type_prefix;
	}

	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			if (service_type) {
				lasso_idwsf2_data_service_set_dst_service_type(query, service_type, prefix);
			}
			lasso_assign_list_of_gobjects(query->QueryItem, service->private_data->query_items);
			g_hash_table_foreach(service->private_data->namespaces,
					(GHFunc)add_custom_namespace,
					query);
			break;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			if (service_type) {
				lasso_idwsf2_data_service_set_dst_service_type(modify, service_type, prefix);
			}
			lasso_assign_list_of_gobjects(modify->ModifyItem, service->private_data->modify_items);
			break;
		default:
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_REQUEST);
			break;
	}
	rc = lasso_idwsf2_profile_build_request_msg(&service->parent, security_mech_id);
cleanup:
	return rc;
}

static gint
lasso_idwsf2_data_service_process_query(LassoIdWsf2DataService *service)
{
	LassoIdWsf2DstRefQuery *query;
	GList *i;
	int rc = 0;

	query = (LassoIdWsf2DstRefQuery*)service->parent.parent.request;
	lasso_check_good_rc(lasso_idwsf2_data_service_set_service_type(
			service,
			query->prefixServiceType,
			query->hrefServiceType));

	/* Parse QueryItems to get a list of Query strings */
	/* FIXME: extract TestItems */
	lasso_foreach(i, query->QueryItem)
	{
		LassoIdWsf2DstRefQueryItem *item = (LassoIdWsf2DstRefQueryItem *)i->data;
		/* FIXME: check more query items invariants. */
		if (! LASSO_IS_IDWSF2_DSTREF_QUERY_ITEM(item)) {
			lasso_release_list_of_gobjects(service->private_data->query_items);
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_REQUEST);
		}
		lasso_list_add_gobject(service->private_data->query_items,
				item);
	}
cleanup:
	return rc;
}

static gint
lasso_idwsf2_data_service_process_modify(LassoIdWsf2DataService *service)
{
	LassoIdWsf2DstRefModify *modify;
	GList *i;
	int rc = 0;

	modify = (LassoIdWsf2DstRefModify*)service->parent.parent.request;
	lasso_foreach(i, modify->ModifyItem)
	{
		LassoIdWsf2DstRefModifyItem *item = (LassoIdWsf2DstRefModifyItem*)i->data;
		/* FIXME: check more Modify Item invariants */
		if (! LASSO_IS_IDWSF2_DSTREF_MODIFY_ITEM(item)) {
			lasso_release_list_of_gobjects(service->private_data->modify_items);
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_REQUEST);
		}
		lasso_list_add_gobject(service->private_data->modify_items, item);
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_process_request_msg:
 * @service: a #LassoIdWsf2DataService object
 * @msg: the message string
 *
 * Process a newly received requests.
 */
gint
lasso_idwsf2_data_service_process_request_msg(LassoIdWsf2DataService *service, const char *msg)
{
	int rc = 0;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);

	lasso_check_good_rc(lasso_idwsf2_profile_process_request_msg(&service->parent, msg));
	lasso_idwsf2_data_service_clean_private_data(service);
	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			rc = lasso_idwsf2_data_service_process_query(service);
			break;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			rc = lasso_idwsf2_data_service_process_modify(service);
			break;
		default:
			rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
			break;
	}
	if (rc == LASSO_PROFILE_ERROR_INVALID_REQUEST) {
		lasso_idwsf2_data_service_set_status_code(service,
				LASSO_DST2_STATUS_CODE1_FAILED,
				"InvalidRequest");
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_validate_request:
 * @service: a #LassoIdWsf2DataService object
 *
 * Initialize a new response object corresponding to the current request. If not request if found or
 * the request is invalid, a failure response is created.
 *
 * Return value: 0 if successful, or LASSO_PROFILE_ERROR_INVALID_REQUEST.
 */
gint
lasso_idwsf2_data_service_validate_request(LassoIdWsf2DataService *service)
{
	LassoIdWsf2DstRefQueryResponse *query_response;
	LassoIdWsf2DstRefModifyResponse *modify_response;
	LassoNode *response = NULL;
	int rc = 0;
	const char *service_type = NULL;
	const char *prefix = NULL;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);

	lasso_check_good_rc(lasso_idwsf2_profile_init_response(&service->parent));
	if (service_type) {
		const char *prefix = lasso_get_prefix_for_idwsf2_dst_service_href(service_type);
		if (! prefix)
			prefix = "dstref";
	} else {
		service_type = service->private_data->service_type;
		prefix = service->private_data->service_type_prefix;
	}
	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			query_response = lasso_idwsf2_dstref_query_response_new();
			if (service_type) {
				lasso_idwsf2_data_service_set_dst_service_type(query_response,
						service_type, prefix);
			}
			response = (LassoNode*)query_response;
			break;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			modify_response = lasso_idwsf2_dstref_modify_response_new();
			if (service_type) {
				lasso_idwsf2_data_service_set_dst_service_type(modify_response,
						service_type, prefix);
			}
			response = (LassoNode*)modify_response;
			break;
		default:
			lasso_idwsf2_data_service_set_status_code(service,
					LASSO_DST2_STATUS_CODE1_FAILED, "InvalidRequest");
			return LASSO_PROFILE_ERROR_INVALID_REQUEST;
	}
	if (response) {
		LassoSoapEnvelope *envelope =
			lasso_idwsf2_profile_get_soap_envelope_response(&service->parent);
		lasso_assign_new_gobject(service->parent.parent.response, response);
		lasso_soap_envelope_add_to_body(envelope, response);
		lasso_idwsf2_data_service_set_status_code(service, LASSO_DST2_STATUS_CODE1_OK, NULL);
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_set_status_code:
 * @service: a #LassoIdWsf2DataService
 * @status_code: a first level status code
 * @status_code2: a second level status code
 *
 * Set the status code for the current response, if no response exists, it starts one using
 * lasso_idwsf2_data_service_validate_request(), if it fails, report a SOAP Fault.
 */
gint
lasso_idwsf2_data_service_set_status_code(LassoIdWsf2DataService *service,
		const char *status_code, const char *status_code2)
{
	LassoNode *response;
	LassoIdWsf2UtilStatus **status = NULL;
	LassoIdWsf2UtilStatus *new_status = NULL;
	int rc = 0;


	response = service->parent.parent.response;
	if (LASSO_IS_IDWSF2_UTIL_RESPONSE(response)) {
		switch (lasso_idwsf2_data_service_get_request_type(service)) {
			case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
				status = &LASSO_IDWSF2_UTIL_RESPONSE(response)->Status;
				break;
			case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
				status = &LASSO_IDWSF2_UTIL_RESPONSE(response)->Status;
				break;
			default:
				break;
		}
	}

	new_status = lasso_idwsf2_util_status_new_with_code(status_code, status_code2);

	if (! LASSO_IS_IDWSF2_UTIL_RESPONSE(response) || ! status) {
		GList details = { .data = new_status, .next = NULL, .prev = NULL };

		lasso_check_good_rc(lasso_idwsf2_profile_init_soap_fault_response(&service->parent,
					LASSO_SOAP_FAULT_CODE_CLIENT, "Unknown Request Type",
					&details));
	} else {
		lasso_assign_gobject(*status, new_status);
	}
cleanup:
	lasso_release_gobject(new_status);
	return rc;
}

/**
 * lasso_idwsf2_data_service_set_query_item_result:
 * @service: a #LassoIdWsf2DataService object
 * @item_id:(allow-none): target a certain QueryItem if NULL, means there is only one query item
 * @xml_data:(allow-none): the data to add
 * @add:(allow-none)(default FALSE): add data to existing datas
 *
 * Set result data for a certain query-item.
 */
gint
lasso_idwsf2_data_service_set_query_item_result(LassoIdWsf2DataService *service,
		const char *item_id, xmlNode *xml_data, gboolean add)
{
	LassoIdWsf2DstRefQueryItem *item;
	LassoIdWsf2DstRefData *data;
	int rc = 0;

	if (lasso_idwsf2_data_service_get_request_type(service)
			!= LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY) {
		goto_cleanup_with_rc(LASSO_IDWSF2_DST_ERROR_ITEM_NOT_FOUND);
	}
	lasso_bad_param(IDWSF2_DATA_SERVICE, service);
	item = (LassoIdWsf2DstRefQueryItem*)lasso_idwsf2_data_service_get_item(service, item_id);
	if (! LASSO_IS_IDWSF2_DSTREF_QUERY_ITEM(item)) {
		goto_cleanup_with_rc(LASSO_IDWSF2_DST_ERROR_ITEM_NOT_FOUND);
	}
	data = lasso_idwsf2_data_service_get_query_item_result(service, item_id);
	if (data == NULL) {
		data = lasso_idwsf2_dstref_data_new();
	}
	if (xml_data) {
		if (! add) {
			lasso_release_list_of_xml_node(data->parent.parent.any);
		}
		lasso_list_add_xml_node(data->parent.parent.any, xml_data);
	}
	if (item_id) {
		lasso_assign_string(data->parent.itemIDRef, item_id);
	}
	if (g_list_find(service->private_data->query_datas, data) == NULL) {
		lasso_list_add_gobject(service->private_data->query_datas, data);
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_build_response_msg:
 * @service: a #LassoIdWsf2DataService object
 *
 * Build the response message corresponding to the current request.
 *
 * Return value: 0 if successfull, an error code otherwise.
 */
gint
lasso_idwsf2_data_service_build_response_msg(LassoIdWsf2DataService *service)
{
	LassoIdWsf2DstRefQueryResponse *query_response;
	GList *datas;
	int rc = 0;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);
	if (! LASSO_IS_SOAP_FAULT(service->parent.parent.response)) {
		switch (lasso_idwsf2_data_service_get_request_type(service)) {
			case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
				goto_cleanup_if_fail_with_rc(
						LASSO_IS_IDWSF2_DSTREF_QUERY_RESPONSE(
							service->parent.parent.response),
						LASSO_PROFILE_ERROR_INVALID_RESPONSE);
				query_response = (LassoIdWsf2DstRefQueryResponse*)service->parent.parent.response;
				datas = lasso_idwsf2_data_service_get_query_item_results(service);
				lasso_assign_list_of_gobjects(query_response->Data, datas);
				break;
			case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
				goto_cleanup_with_rc(LASSO_ERROR_UNIMPLEMENTED);
				break;
			default:
				break;
		}
	}
	rc = lasso_idwsf2_profile_build_response_msg(&service->parent);
cleanup:
	return rc;
}

static gint
_lasso_idwsf2_data_service_process_query_response(LassoIdWsf2DataService * service,
		LassoIdWsf2DstRefQueryResponse *response)
{
	int rc = 0;

	goto_cleanup_if_fail_with_rc(LASSO_IS_IDWSF2_DSTREF_QUERY_RESPONSE(response),
			LASSO_PROFILE_ERROR_INVALID_RESPONSE);

	if (service->private_data) {
		lasso_assign_list_of_gobjects(service->private_data->query_datas, response->Data);
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_process_response_msg:
 * @service: a #LassoIdWsf2DataService object
 * @msg: (allow-none): the message content
 *
 * Process a received SOAP message response.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_data_service_process_response_msg(
	LassoIdWsf2DataService *service, const char *msg)
{
	LassoIdWsf2DstRefQueryResponse *query_response;
	LassoIdWsf2UtilStatus *status;
	int rc = 0;

	lasso_bad_param(IDWSF2_DATA_SERVICE, service);

	lasso_check_good_rc(lasso_idwsf2_profile_process_response_msg(&service->parent, msg));

	status = lasso_idwsf2_data_service_get_response_status(service);

	if (! status || ! status->code) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_STATUS_CODE);
	}
	if (lasso_strisequal(status->code,LASSO_DST2_STATUS_CODE1_FAILED)) {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS);
	}
	if (lasso_strisequal(status->code,LASSO_DST2_STATUS_CODE1_PARTIAL)) {
		rc = LASSO_IDWSF2_DST_ERROR_PARTIAL_FAILURE;
	}
	if (lasso_strisnotequal(status->code,LASSO_DST2_STATUS_CODE1_OK)) {
		rc = LASSO_IDWSF2_DST_ERROR_UNKNOWN_STATUS_CODE;
	}

	switch (lasso_idwsf2_data_service_get_request_type(service)) {
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_QUERY:
			query_response = (LassoIdWsf2DstRefQueryResponse*)service->parent.parent.response;
			lasso_check_good_rc(_lasso_idwsf2_data_service_process_query_response(service, query_response));
			break;
		case LASSO_IDWSF2_DATA_SERVICE_REQUEST_TYPE_MODIFY:
			rc = LASSO_ERROR_UNIMPLEMENTED;
			break;
		default:
			rc = LASSO_ERROR_UNDEFINED;
			break;
	}

cleanup:
	return rc;
}

/**
 * lasso_idwsf2_data_service_get_response_status:
 * @service: a #LassoIdWsf2UtilStatus object
 *
 * Return the status from the current response.
 *
 * Return value:(transfer none)(allow-none): a #LassoIdWsf2UtilStatus object, or NULL.
 */
LassoIdWsf2UtilStatus*
lasso_idwsf2_data_service_get_response_status(LassoIdWsf2DataService *service)
{
	LassoIdWsf2UtilResponse *response;
	LassoSoapFault *fault;

	response = (void*)(fault = (void*)service->parent.parent.response);
	if (LASSO_IS_IDWSF2_UTIL_RESPONSE(response)) {
		return response->Status;
	}
	if (LASSO_IS_SOAP_FAULT(fault)) {
		if (LASSO_IS_SOAP_DETAIL(fault->Detail) && fault->Detail->any
				&& LASSO_IS_IDWSF2_UTIL_STATUS(fault->Detail->any->data)) {
			return (LassoIdWsf2UtilStatus*)fault->Detail->any->data;
		}
	}
	return NULL;
}

/**
 * lasso_idwsf2_data_service_get_query_item_result:
 * @service: a #LassoIdWsf2DataService object
 * @item_id:(allow-none): an item_id or NULL if only one data is present
 *
 * Return value:(allow-none)(transfer none): a #LassoIdWsf2DstRefData or NULL if none is found.
 */
LassoIdWsf2DstRefData*
lasso_idwsf2_data_service_get_query_item_result(LassoIdWsf2DataService *service,
		const char *item_id)
{
	GList *i;

	if (! LASSO_IS_IDWSF2_DATA_SERVICE(service))
		return NULL;
	if (! item_id) {
		if (g_list_length(service->private_data->query_datas) == 1) {
			return (LassoIdWsf2DstRefData*)service->private_data->query_datas->data;
		}
		return NULL;
	}
	lasso_foreach(i, service->private_data->query_datas) {
		LassoIdWsf2DstRefData *data = (LassoIdWsf2DstRefData*)i->data;
		if (lasso_strisequal(data->parent.itemIDRef,item_id)) {
			return data;
		}
	}
	return NULL;
}

/**
 * lasso_idwsf2_data_service_get_query_item_result_content:
 * @service: a #LassoIdWsf2DataService object
 * @item_id:(allow-none): the identifier of the result asked, if NULL and there is only one respone,
 * returns it.
 *
 * Returns the text content of the query item result identified by @item_id or the only query item
 * result if @item_id is NULL.
 * <para>If @item_id is NULL and there is multiple results, returns NULL.</para>
 *
 * Return value:(transfer full): the text content of the query item result.
 */
char*
lasso_idwsf2_data_service_get_query_item_result_content(LassoIdWsf2DataService *service,
		const char *item_id)
{
	LassoIdWsf2DstRefData *data = NULL;
	LassoIdWsf2DstRefAppData *app_data = NULL;
	GList *i = NULL;
	GString *gstr = NULL;
	char *result = NULL;

	data = lasso_idwsf2_data_service_get_query_item_result(service, item_id);
	if (! data)
		return NULL;
	app_data = (LassoIdWsf2DstRefAppData*)data;
	gstr = g_string_sized_new(128);
	lasso_foreach(i, app_data->any) {
		xmlNode *node = (xmlNode*)i->data;
		xmlChar *content;
		content = xmlNodeGetContent(node);
		g_string_append(gstr, (char*)content);
		xmlFree(content);
	}
	result = gstr->str;
	lasso_release_gstring(gstr, FALSE);
	return result;
}

/**
 * lasso_idwsf2_data_service_get_query_item_results:
 * @service: a #LassoIdWsf2DataService object
 *
 * Return value:(allow-none)(transfer none)(element-type LassoIdWsf2DstRefData): the list of
 * #LassoIdWsf2DstRefData or NULL if none is found.
 */
GList*
lasso_idwsf2_data_service_get_query_item_results(LassoIdWsf2DataService *service)
{

	if (LASSO_IS_IDWSF2_DATA_SERVICE(service) && service->private_data) {
		return service->private_data->query_datas;
	}
	return NULL;
}

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoIdWsf2DataService *service = LASSO_IDWSF2_DATA_SERVICE(object);
	LassoIdWsf2DataServicePrivate *pdata = service->private_data;

	if (!pdata || pdata->dispose_has_run == TRUE)
		return;
	pdata->dispose_has_run = TRUE;

	lasso_idwsf2_data_service_clean_private_data(service);
	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoIdWsf2DataService *service = LASSO_IDWSF2_DATA_SERVICE(object);
	lasso_release(service->private_data);
	service->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

static void
instance_init(LassoIdWsf2DataService *service)
{
	service->private_data = g_new0(LassoIdWsf2DataServicePrivate, 1);
	service->private_data->namespaces = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free, (GDestroyNotify)g_free);
}

static void
class_init(LassoIdWsf2DataServiceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	lasso_node_class_set_nodename(LASSO_NODE_CLASS(klass), "IdWsf2DataService");
	lasso_node_class_set_ns(LASSO_NODE_CLASS(klass), LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
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
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_PROFILE,
				"LassoIdWsf2DataService", &this_info, 0);
	}
	return this_type;
}


/**
 * lasso_idwsf2_data_service_new:
 * @server:(allow-none): a #LassoServer object, for resolving ProviderIDs
 *
 * Create a new #LassoIdWsf2DataService.
 *
 * Return value: a newly created #LassoIdWsf2DataService object
 **/
LassoIdWsf2DataService*
lasso_idwsf2_data_service_new(LassoServer *server)
{
	LassoIdWsf2DataService *service;

	service = g_object_new(LASSO_TYPE_IDWSF2_DATA_SERVICE, NULL);
	service->parent.parent.server = lasso_ref(server);

	return service;
}
