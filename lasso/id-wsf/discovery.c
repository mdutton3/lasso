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

#include <lasso/xml/disco_modify.h>
#include <lasso/xml/disco_modify_response.h>
#include <lasso/xml/disco_query.h>
#include <lasso/xml/disco_query_response.h>

#include <lasso/xml/disco_insert_entry.h>
#include <lasso/xml/disco_remove_entry.h>

#include <lasso/id-wsf/discovery.h>

struct _LassoDiscoveryPrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* static methods/functions */
/*****************************************************************************/

/**
 * lasso_discovery_init_request:
 * @discovery: a LassoDiscovery
 * @resourceOffering: a LassoDiscoResourceOffering
 * @description: a LassoDiscoDescription
 * 
 * Generic static method used by lasso_discovery_init_modify() and lasso_discovery_init_query() 
 * 
 * Return value: 0 on success and a negative value if an error occurs.
 **/
static gint
lasso_discovery_init_request(LassoDiscovery             *discovery,
			     LassoDiscoResourceOffering *resourceOffering,
			     LassoDiscoDescription      *description)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(discovery);

	/* verify that description is present in resourceOffering->ServiceInstance->Description */
	if (g_list_find(resourceOffering->ServiceInstance->Description, description) == NULL) {
		message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_PARAM_ERROR_INVALID_VALUE));
	}
	/* get ResourceID/EncryptedResourceID in description */
	if (resourceOffering->ResourceID != NULL) {
		if (LASSO_IS_DISCO_MODIFY(profile->request)) {
			LASSO_DISCO_MODIFY(profile->request)->ResourceID = \
				resourceOffering->ResourceID;
		}
		else if (LASSO_IS_DISCO_QUERY(profile->request)) {
			LASSO_DISCO_QUERY(profile->request)->ResourceID = \
				resourceOffering->ResourceID;
		}
	}
	else if (resourceOffering->EncryptedResourceID != NULL) {
		if (LASSO_IS_DISCO_MODIFY(profile->request)) {
			LASSO_DISCO_MODIFY(profile->request)->EncryptedResourceID = \
				resourceOffering->EncryptedResourceID;
		}
		else if (LASSO_IS_DISCO_QUERY(profile->request)) {
			LASSO_DISCO_QUERY(profile->request)->EncryptedResourceID = \
				resourceOffering->EncryptedResourceID;
		}
	}
	if (description->Endpoint != NULL) {
		profile->msg_url = description->Endpoint;
	}
	else if (description->WsdlURI != NULL) {
		/* TODO: get Endpoint at WsdlURI */
	}

	return 0;
}

/*****************************************************************************/
/* public methods */
/*****************************************************************************/

LassoDiscoInsertEntry*
lasso_discovery_add_insert_entry(LassoDiscovery                *discovery,
				 const gchar                   *serviceType,
				 const gchar                   *providerID,
				 GList                         *descriptions,
				 LassoDiscoResourceID          *resourceID,
				 LassoDiscoEncryptedResourceID *encryptedResourceID,
				 GList                         *options)
{
	LassoDiscoModify *modify;
	LassoDiscoInsertEntry *entry;
	LassoDiscoResourceOffering *resource;
	LassoDiscoServiceInstance *service;
	LassoDiscoOptions *opts;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), NULL);
	g_return_val_if_fail(serviceType!= NULL, NULL);
	g_return_val_if_fail(providerID != NULL, NULL);
	/* only one description is required */
	g_return_val_if_fail(g_list_length(descriptions) >= 1, NULL);
	/* resourceID/encryptedResourceID and options are optionals */
	g_return_val_if_fail((resourceID == NULL && encryptedResourceID == NULL) || \
			     (LASSO_IS_DISCO_RESOURCE_ID(resourceID) ^	\
			      LASSO_IS_DISCO_ENCRYPTED_RESOURCE_ID(encryptedResourceID)), NULL);

	modify = LASSO_DISCO_MODIFY(LASSO_WSF_PROFILE(discovery)->request);

	/* create InsertEntry */
	entry = lasso_disco_insert_entry_new();
	/* create ServiceInstance */
	service = lasso_disco_service_instance_new(serviceType, providerID, descriptions);
	/* create ResourceOffering */
	resource = lasso_disco_resource_offering_new(service);
	resource->ResourceID = resourceID;
	resource->EncryptedResourceID = encryptedResourceID;

	/* optionals data */
	/* create Options */
	if (options != NULL) {
		opts = lasso_disco_options_new();
		while (options != NULL) {
			opts->Option = g_list_append(opts->Option, options->data);
			options = g_list_next(options);
		}
		resource->Options = opts;
	}
	entry->ResourceOffering = resource;

	/* add InsertEntry */
	modify->InsertEntry = g_list_append(modify->InsertEntry, (gpointer)entry);

	return entry;
}

gint
lasso_discovery_add_remove_entry(LassoDiscovery *discovery,
				 const gchar    *entryID)
{
	LassoDiscoModify *modify;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(entryID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	modify = LASSO_DISCO_MODIFY(LASSO_WSF_PROFILE(discovery)->request);
	/* add RemoveEntry */
	modify->RemoveEntry = g_list_append(modify->RemoveEntry,
					    (gpointer)lasso_disco_remove_entry_new(entryID));

	return 0;
}

LassoDiscoRequestedServiceType*
lasso_discovery_add_requested_service_type(LassoDiscovery *discovery,
					   const gchar    *serviceType,
					   GList          *options)
{
	LassoDiscoQuery *query;
	LassoDiscoRequestedServiceType *rst;
	LassoDiscoOptions *opts;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), NULL);
	g_return_val_if_fail(serviceType != NULL, NULL);
	/* options is optional */

	query = LASSO_DISCO_QUERY(LASSO_WSF_PROFILE(discovery)->request);

	rst = lasso_disco_requested_service_type_new(serviceType);

	/* optionals data */
	/* create Options */
	if (options != NULL) {
		opts = lasso_disco_options_new();
		while (options != NULL) {
			opts->Option = g_list_append(opts->Option, options->data);
			options = g_list_next(options);
		}
		rst->Options = opts;
	}

	/* add RequestedServiceType */
	query->RequestedServiceType = g_list_append(query->RequestedServiceType, (gpointer)rst);

	return rst;
}

gint
lasso_discovery_add_resource_offering(LassoDiscovery             *discovery,
				      LassoDiscoResourceOffering *resourceOffering)
{
	LassoDiscoQueryResponse *query_response;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	query_response = LASSO_DISCO_QUERY_RESPONSE(LASSO_WSF_PROFILE(discovery)->response);

	/* add ResourceOffering */
	query_response->ResourceOffering = g_list_append(query_response->ResourceOffering,
							 (gpointer)resourceOffering);
	
	return 0;
}

/**
 * lasso_discovery_destroy:
 * @discovery: a LassoDiscovery
 * 
 * Destroys LassoDiscovery objects created with lasso_discovery_new() or
 * lasso_discovery_new_from_dump().
 **/
void
lasso_discovery_destroy(LassoDiscovery *discovery)
{
	g_object_unref(G_OBJECT(discovery));
}

gint
lasso_discovery_init_modify(LassoDiscovery                *discovery,
			    LassoDiscoResourceOffering    *resourceOffering,
			    LassoDiscoDescription         *description)
{
	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(lasso_disco_modify_new());
	/*
	 * after the call of this method, app must add InsertEntry and RemoveEntry
	 */
	return lasso_discovery_init_request(discovery, resourceOffering, description);
}

gint
lasso_discovery_init_query(LassoDiscovery                *discovery,
			   LassoDiscoResourceOffering    *resourceOffering,
			   LassoDiscoDescription         *description)
{
	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(lasso_disco_query_new());
	/*
	 * after the call of this method, app must add requested service types
	 */
	return lasso_discovery_init_request(discovery, resourceOffering, description);
}

gint
lasso_discovery_process_modify_msg(LassoDiscovery *discovery,
				   const gchar    *message)
{
	LassoDiscoModify *request;
	LassoDiscoModifyResponse *response;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	request = lasso_disco_modify_new_from_message(message);
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(request);
	/* App should process insert entries and remove entries (in ResourceOffering) */

	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_disco_modify_response_new(status);
	LASSO_WSF_PROFILE(discovery)->response = LASSO_NODE(response);

	return 0;
}

gint
lasso_discovery_process_modify_response_msg(LassoDiscovery *discovery, const gchar *message)
{
	LASSO_WSF_PROFILE(discovery)->response =
		LASSO_NODE(lasso_disco_modify_new_from_message(message));

	return 0;
}

gint
lasso_discovery_process_query_msg(LassoDiscovery *discovery, const gchar *message)
{
	LassoDiscoQuery *request;
	LassoDiscoQueryResponse *response;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	request = lasso_disco_query_new_from_message(message);
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(request);

	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_disco_query_response_new(status);
	LASSO_WSF_PROFILE(discovery)->response = LASSO_NODE(response);

	/*
	 * after the call of this method, app must add ResourceOffering
	 */

	return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoDiscovery *discovery = LASSO_DISCOVERY(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "Discovery");
	xmlSetProp(xmlnode, "DiscoveryDumpVersion", "2");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoDiscovery *discovery = LASSO_DISCOVERY(node);
	xmlNode *t;
	int rc;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	return 0;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoDiscovery *discovery = LASSO_DISCOVERY(object);

	if (discovery->private_data->dispose_has_run == TRUE) {
		return;
	}
	discovery->private_data->dispose_has_run = TRUE;

	debug("Discovery object 0x%p disposed ...", discovery);

	/* unref reference counted objects */

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoDiscovery *discovery = LASSO_DISCOVERY(object);

	debug("Discovery object 0x%p finalized ...", discovery);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoDiscovery *discovery)
{
	discovery->private_data = g_new(LassoDiscoveryPrivate, 1);
	discovery->private_data->dispose_has_run = FALSE;
}

static void
class_init(LassoDiscoveryClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_discovery_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoDiscoveryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscovery),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
						   "LassoDiscovery", &this_info, 0);
	}
	return this_type;
}

LassoDiscovery*
lasso_discovery_new(LassoServer *server)
{
	LassoDiscovery *discovery = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	discovery = g_object_new(LASSO_TYPE_DISCOVERY, NULL);
	LASSO_WSF_PROFILE(discovery)->server = server;

	return discovery;
}

LassoDiscovery*
lasso_discovery_new_from_dump(LassoServer *server, const gchar *dump)
{
	LassoDiscovery *discovery;
	xmlDoc *doc;

	discovery = g_object_new(LASSO_TYPE_DISCOVERY, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(discovery), xmlDocGetRootElement(doc)); 
	LASSO_WSF_PROFILE(discovery)->server = server;

	return discovery;
}

gchar*
lasso_discovery_dump(LassoDiscovery *discovery)
{
	return lasso_node_dump(LASSO_NODE(discovery), NULL, 1);
}

