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

#include <lasso/id-wsf/discovery.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/saml_assertion.h>
#include <lasso/xml/saml_attribute_value.h>

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
	/* ResourceID and EncryptedResourceID are owned by resourceOffering,
	 so increment reference count */
	if (resourceOffering->ResourceID != NULL) {
		g_object_ref(resourceOffering->ResourceID);
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
		g_object_ref(resourceOffering->EncryptedResourceID);
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
		profile->msg_url = g_strdup(description->Endpoint);
	}
	else if (description->WsdlURI != NULL) {
		/* TODO: get Endpoint at WsdlURI */
	}

	return 0;
}

LassoDiscoInsertEntry*
lasso_discovery_add_insert_entry(LassoDiscovery *discovery,
				 LassoDiscoServiceInstance *serviceInstance,
				 LassoDiscoResourceID *resourceId)
{
	LassoDiscoModify *modify;
	LassoDiscoInsertEntry *insertEntry;
	LassoDiscoResourceOffering *resourceOffering;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_SERVICE_INSTANCE(serviceInstance), NULL);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_ID(resourceId), NULL);

	modify = LASSO_DISCO_MODIFY(LASSO_WSF_PROFILE(discovery)->request);

	/* ResourceOffering elements being inserted MUST NOT contain entryID attributes. */
	serviceInstance = serviceInstance ? g_object_ref(serviceInstance) : serviceInstance;
	resourceOffering = lasso_disco_resource_offering_new(serviceInstance);

	resourceId = resourceId ? g_object_ref(resourceId) : resourceId;
	resourceOffering->ResourceID = resourceId;

	insertEntry = lasso_disco_insert_entry_new(resourceOffering);

	modify->InsertEntry = g_list_append(modify->InsertEntry, insertEntry);

	return insertEntry;
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
					    lasso_disco_remove_entry_new(entryID));

	return 0;
}

LassoDiscoRequestedServiceType*
lasso_discovery_add_requested_service_type(LassoDiscovery *discovery,
					   const gchar    *serviceType,
					   const gchar     *option)
{
	LassoDiscoQuery *query;
	LassoDiscoRequestedServiceType *rst;
	LassoDiscoOptions *opts = NULL;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), NULL);
	g_return_val_if_fail(serviceType != NULL, NULL);
	/* option is optional */

	query = LASSO_DISCO_QUERY(LASSO_WSF_PROFILE(discovery)->request);

	rst = lasso_disco_requested_service_type_new(serviceType);

	/* optionals data */
	if (option != NULL) {
		opts = lasso_disco_options_new();
		opts->Option = g_list_append(opts->Option, (gpointer)option);
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
	LassoSoapEnvelope *envelope;
	LassoDiscoModify *modify;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	modify = lasso_disco_modify_new();
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(modify);

	envelope = lasso_wsf_profile_build_soap_envelope(NULL);
	LASSO_WSF_PROFILE(discovery)->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, modify);

	return lasso_discovery_init_request(discovery, resourceOffering, description);
}

gint
lasso_discovery_init_query(LassoDiscovery                *discovery,
			   LassoDiscoResourceOffering    *resourceOffering,
			   LassoDiscoDescription         *description)
{
	LassoDiscoQuery *query;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(resourceOffering),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	query = lasso_disco_query_new();
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(query);

	lasso_wsf_profile_init_soap_request(LASSO_WSF_PROFILE(discovery), LASSO_NODE(query));

	return lasso_discovery_init_request(discovery, resourceOffering, description);
}

static LassoDiscoResourceOffering*
lasso_discovery_get_resource_offering_auto(LassoDiscovery *discovery, const gchar *service_type)
{
	LassoSession *session;
	GList *assertions, *iter, *iter2, *iter3, *iter4;
	LassoDiscoResourceOffering *resource_offering = NULL;

	session = LASSO_WSF_PROFILE(discovery)->session;
	assertions = lasso_session_get_assertions(session, NULL);
	iter = assertions;
	while (iter) {
		LassoSamlAssertion *assertion = iter->data;
		iter = g_list_next(iter);
		if (assertion->AttributeStatement == NULL)
			continue;
		iter2 = assertion->AttributeStatement->Attribute;
		while (iter2) {
			LassoSamlAttribute *attribute = iter2->data;
			iter2 = g_list_next(iter2);
			if (strcmp(attribute->attributeName, "DiscoveryResourceOffering") != 0)
				continue;
			iter3 = attribute->AttributeValue;
			while (iter3) {
				LassoSamlAttributeValue *attribute_value = iter3->data;
				iter3 = g_list_next(iter3);
				iter4 = attribute_value->any;
				while (iter4) {
					LassoDiscoResourceOffering *v = iter4->data;
					iter4 = g_list_next(iter4);
					if (! LASSO_IS_DISCO_RESOURCE_OFFERING(v))
						continue;
					if (v->ServiceInstance == NULL)
						continue;
					if (strcmp(v->ServiceInstance->ServiceType,
								service_type) == 0) {
						resource_offering = v;
						goto end;
					}
				}
			}
		}
	}

end:
	return g_object_ref(resource_offering);
}


/**
 * lasso_discovery_init_insert
 * @discovery: a #LassoDiscovery
 * @new_offering: the new service offered
 *
 * Initializes a disco Modify/InsertEntry
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_discovery_init_insert(LassoDiscovery *discovery, LassoDiscoResourceOffering *new_offering)
{
	LassoDiscoModify *modify;
	LassoSession *session;
	GList *assertions;
	LassoDiscoResourceOffering *offering;

	modify = lasso_disco_modify_new();
	lasso_wsf_profile_init_soap_request(LASSO_WSF_PROFILE(discovery), LASSO_NODE(modify));

	/* get discovery service resource id from principal assertion */
	offering = lasso_discovery_get_resource_offering_auto(discovery, LASSO_DISCO_HREF);
	if (offering == NULL) {
		return -1;
	}
	/* XXX: EncryptedResourceID support */
	modify->ResourceID = g_object_ref(offering->ResourceID);
	lasso_node_destroy(LASSO_NODE(offering));

	modify->InsertEntry = g_list_append(modify->InsertEntry,
			lasso_disco_insert_entry_new(new_offering));
	LASSO_WSF_PROFILE(discovery)->request = LASSO_NODE(modify);

	return 0;
}

gint
lasso_discovery_process_modify_msg(LassoDiscovery *discovery,
				   const gchar    *message)
{
	LassoDiscoModifyResponse *response;
	LassoSoapEnvelope *envelope;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	lasso_wsf_profile_process_soap_request_msg(LASSO_WSF_PROFILE(discovery), message);

	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_disco_modify_response_new(status);
	LASSO_WSF_PROFILE(discovery)->response = LASSO_NODE(response);

	envelope = LASSO_WSF_PROFILE(discovery)->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return 0;
}

gint
lasso_discovery_process_modify_response_msg(LassoDiscovery *discovery, const gchar *message)
{
	return lasso_wsf_profile_process_soap_response_msg(LASSO_WSF_PROFILE(discovery), message);
}

gint
lasso_discovery_process_query_msg(LassoDiscovery *discovery, const gchar *message)
{
	LassoDiscoQueryResponse *response;
	LassoSoapEnvelope *envelope;
	LassoUtilityStatus *status;

	g_return_val_if_fail(LASSO_IS_DISCOVERY(discovery), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	lasso_wsf_profile_process_soap_request_msg(LASSO_WSF_PROFILE(discovery), message);

	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_disco_query_response_new(status);
	LASSO_WSF_PROFILE(discovery)->response = LASSO_NODE(response);

	envelope = LASSO_WSF_PROFILE(discovery)->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return 0;
}

gint
lasso_discovery_process_query_response_msg(LassoDiscovery *discovery, const gchar *message)
{
	return lasso_wsf_profile_process_soap_response_msg(LASSO_WSF_PROFILE(discovery), message);
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)"Discovery");
	xmlSetProp(xmlnode, (xmlChar*)"DiscoveryDumpVersion", (xmlChar*)"2");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
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

	if (discovery->private_data->dispose_has_run == TRUE)
		return;
	discovery->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoDiscovery *discovery = LASSO_DISCOVERY(object);
	g_free(discovery->private_data);
	discovery->private_data = NULL;
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
	return lasso_node_dump(LASSO_NODE(discovery));
}

