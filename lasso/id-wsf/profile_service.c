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
#include <lasso/xml/soap_binding_correlation.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_profile_service_add_data(LassoProfileService *service, const gchar *xmlNodeBuffer)
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
	LassoSoapBindingCorrelation *correlation;
	LassoSoapEnvelope *envelope;
	LassoUtilityStatus *status;
	LassoWsfProfile *profile;
	gchar *messageId;

	g_return_val_if_fail(LASSO_IS_PROFILE_SERVICE(service), -1);
	g_return_val_if_fail(soap_msg != NULL, -1);

	profile = LASSO_WSF_PROFILE(service);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(soap_msg));
	LASSO_WSF_PROFILE(service)->soap_envelope_request = envelope;
	LASSO_WSF_PROFILE(service)->request = LASSO_NODE(envelope->Body->any->data);

	correlation = envelope->Header->Other->data;
	messageId = correlation->messageID;
	envelope = lasso_wsf_profile_build_soap_envelope(messageId);
	LASSO_WSF_PROFILE(service)->soap_envelope_response = envelope;

	/* init QueryResponse */
	status = lasso_utility_status_new(LASSO_DST_STATUS_CODE_OK);
	response = lasso_dst_query_response_new(status);
	LASSO_WSF_PROFILE(service)->response = LASSO_NODE(response);
	LASSO_DST_QUERY_RESPONSE(profile->response)->prefixServiceType = g_strdup(prefix);
	LASSO_DST_QUERY_RESPONSE(profile->response)->hrefServiceType = g_strdup(href);

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
