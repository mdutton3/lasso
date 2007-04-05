/* $Id: wsf_profile.c,v 1.45 2007/01/05 16:11:02 Exp $
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

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/id-wsf-2.0/wsf2_profile.h>
#include <lasso/xml/soap_fault.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/soap_binding_processing_context.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/providerprivate.h>

#include <lasso/id-wsf-2.0/wsf2_profile_private.h>

struct _LassoWsf2ProfilePrivate
{
	gboolean dispose_has_run;
	LassoSoapFault *fault;
	gchar *public_key;
	GList *credentials;
};


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

LassoSoapEnvelope*
lasso_wsf2_profile_build_soap_envelope(const char *refToMessageId, const char *providerId)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;
	LassoSoapBindingCorrelation *correlation;
	gchar *messageId, *timestamp;

	/* Body */
	body = lasso_soap_body_new();
	body->id = lasso_build_unique_id(32);
	envelope = lasso_soap_envelope_new(body);

	/* Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	/* Correlation */
	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
	correlation->id = lasso_build_unique_id(32);
	if (refToMessageId != NULL)
		correlation->refToMessageID = g_strdup(refToMessageId);
	header->Other = g_list_append(header->Other, correlation);

	/* Provider */
	if (providerId) {
		LassoSoapBindingProvider *provider = lasso_soap_binding_provider_new(providerId);
		provider->id = lasso_build_unique_id(32);
		header->Other = g_list_append(header->Other, provider);
	}

	return envelope;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_wsf2_profile_init_soap_request(LassoWsf2Profile *profile, LassoNode *request)
{
	LassoSoapEnvelope *envelope;

	envelope = lasso_wsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_WSF2_PROFILE(profile)->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, request);

	return 0;
}

gint
lasso_wsf2_profile_build_soap_request_msg(LassoWsf2Profile *profile)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	int ret;
	GList *iter = NULL;
	xmlNode *security_xmlNode, *credential;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	xmlDoc *doc = NULL;
	xmlNode *envelope_node = NULL;
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj = NULL;
			

	g_return_val_if_fail(LASSO_IS_WSF2_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	envelope = profile->soap_envelope_request;

	doc = xmlNewDoc((xmlChar*)"1.0");
	envelope_node = lasso_node_get_xmlNode(LASSO_NODE(envelope), FALSE);
	xmlDocSetRootElement(doc, envelope_node);

	/* Dump soap request */
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, envelope_node, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);
	xmlFreeDoc(doc);

	return 0;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(object);

	if (profile->private_data->dispose_has_run == TRUE)
		return;
	profile->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(object);
	g_free(profile->private_data);
	profile->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsf2Profile *profile)
{
	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->soap_envelope_request = NULL;
	profile->soap_envelope_response = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
	
	profile->private_data = g_new0(LassoWsf2ProfilePrivate, 1);
	profile->private_data->dispose_has_run = FALSE;
	profile->private_data->fault = NULL;
	profile->private_data->credentials = NULL;
}

static void
class_init(LassoWsf2ProfileClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_wsf2_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoWsf2ProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsf2Profile),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsf2Profile", &this_info, 0);
	}
	return this_type;
}

LassoWsf2Profile*
lasso_wsf2_profile_new(LassoServer *server)
{
	LassoWsf2Profile *profile = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	profile = g_object_new(LASSO_TYPE_WSF2_PROFILE, NULL);

	return profile;
}
