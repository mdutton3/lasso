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

#include <lasso/id-ff/lecp.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/


/**
 * lasso_lecp_build_authn_request_envelope_msg:
 * @lecp: a #LassoLecp
 *
 * Builds an enveloped authentication request message.  Sets @msg_body to that
 * message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp)
{
	LassoProfile *profile;
	gchar *assertionConsumerServiceURL;
	xmlNode *message;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);

	assertionConsumerServiceURL = lasso_provider_get_assertion_consumer_service_url(
			LASSO_PROVIDER(profile->server), NULL);
	if (assertionConsumerServiceURL == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	if (profile->request == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnRequest not found");
		return LASSO_ERROR_UNDEFINED;
	}

	lecp->authnRequestEnvelope = lasso_lib_authn_request_envelope_new_full(
			LASSO_LIB_AUTHN_REQUEST(profile->request),
			LASSO_PROVIDER(profile->server)->ProviderID,
			assertionConsumerServiceURL);
	if (lecp->authnRequestEnvelope == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
	}

	LASSO_SAMLP_REQUEST_ABSTRACT(lecp->authnRequestEnvelope->AuthnRequest)->private_key_file =
		LASSO_PROFILE(lecp)->server->private_key;
	LASSO_SAMLP_REQUEST_ABSTRACT(lecp->authnRequestEnvelope->AuthnRequest)->certificate_file =
		LASSO_PROFILE(lecp)->server->certificate;
	message = lasso_node_get_xmlNode(LASSO_NODE(lecp->authnRequestEnvelope), FALSE);
	
	/* message is not SOAP but straight XML */
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler); 
	xmlNodeDumpOutput(buf, NULL, message, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);

	profile->msg_body = g_strdup(buf->conv ? buf->conv->content : buf->buffer->content);
	xmlOutputBufferClose(buf);
	xmlFreeNode(message);

	if (profile->msg_body == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				"Error while exporting the AuthnRequestEnvelope to POST msg");
		return LASSO_ERROR_UNDEFINED;
	}

	return 0;
}

/**
 * lasso_lecp_build_authn_request_msg:
 * @lecp: a #LassoLecp
 * 
 * Builds an authentication request. The data for the sending of the request are
 * stored in @msg_url and @msg_body (SOAP POST).
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_lecp_build_authn_request_msg(LassoLecp *lecp)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);

	profile->msg_url  = lasso_provider_get_metadata_one(
			remote_provider, "SingleSignOnServiceURL");
	/* msg_body has usally been set in
	 * lasso_lecp_process_authn_request_envelope_msg() */
	if (profile->msg_body == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);

	return 0;
}


/**
 * lasso_lecp_build_authn_response_msg:
 * @lecp: a #LassoLecp
 *
 * Builds the lecp authentication response message (base64).  Sets @msg_body to
 * that message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_lecp_build_authn_response_msg(LassoLecp *lecp)
{
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);
	profile->msg_url = g_strdup(lecp->assertionConsumerServiceURL);
	if (profile->msg_url == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}
	profile->msg_body = lasso_node_export_to_base64(LASSO_NODE(profile->response));
	if (profile->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}


/**
 * lasso_lecp_build_authn_response_envelope_msg:
 * @lecp: a #LassoLecp
 *
 * Builds the enveloped LECP authentication response message (SOAP message).
 * Sets @msg_body to that message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp)
{
	LassoProfile  *profile;
	LassoProvider *provider;
	gchar *assertionConsumerServiceURL;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	profile = LASSO_PROFILE(lecp);

	if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found");
		return LASSO_ERROR_UNDEFINED;
	}

	provider = g_hash_table_lookup(profile->server->providers, profile->remote_providerID);
	if (provider == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	/* build lib:AuthnResponse */
	lasso_login_build_authn_response_msg(LASSO_LOGIN(lecp));

	assertionConsumerServiceURL = lasso_provider_get_assertion_consumer_service_url(
			provider, NULL);
	if (assertionConsumerServiceURL == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	if (LASSO_PROFILE(lecp)->msg_body)
		g_free(LASSO_PROFILE(lecp)->msg_body);

	if (LASSO_PROFILE(lecp)->msg_url)
		g_free(LASSO_PROFILE(lecp)->msg_url);
	LASSO_PROFILE(lecp)->msg_url = NULL;

	lecp->authnResponseEnvelope = lasso_lib_authn_response_envelope_new(
			LASSO_LIB_AUTHN_RESPONSE(profile->response),
			assertionConsumerServiceURL);
	LASSO_SAMLP_RESPONSE_ABSTRACT(lecp->authnResponseEnvelope->AuthnResponse
			)->private_key_file = profile->server->private_key;
	LASSO_SAMLP_RESPONSE_ABSTRACT(lecp->authnResponseEnvelope->AuthnResponse
			)->certificate_file = profile->server->certificate;
	profile->msg_body = lasso_node_export_to_soap(LASSO_NODE(lecp->authnResponseEnvelope));

	if (profile->msg_body == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED);
	}

	return 0;
}

/**
 * lasso_lecp_init_authn_request:
 * @lecp: a #LassoLecp
 * @remote_providerID: the providerID of the identity provider. When NULL, the
 *     first known identity provider is used.
 *
 * Initializes a new lib:AuthnRequest.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_lecp_init_authn_request(LassoLecp *lecp, const char *remote_providerID)
{
	gint res;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);

	/* FIXME : BAD usage of http_method
	   using POST method so that the lib:AuthnRequest is initialize with
	   a signature template */
	res = lasso_login_init_authn_request(LASSO_LOGIN(lecp), remote_providerID,
			LASSO_HTTP_METHOD_POST);

	return res;
}


/**
 * lasso_lecp_process_authn_request_msg:
 * @lecp: a #LassoLecp
 * @authn_request_msg: the authentication request received
 *
 * Processes received authentication request, checks it is signed correctly,
 * checks if requested protocol profile is supported, etc.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_lecp_process_authn_request_msg(LassoLecp *lecp, const char *authn_request_msg)
{
	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
	g_return_val_if_fail(authn_request_msg != NULL, -1);

	return lasso_login_process_authn_request_msg(LASSO_LOGIN(lecp), authn_request_msg);
}


/**
 * lasso_lecp_process_authn_request_envelope_msg:
 * @lecp: a #LassoLecp
 * @request_msg: the enveloped authentication request received
 *
 * Processes received enveloped authentication request, extracts the
 * authentication request out of it.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp, const char *request_msg)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *soap_envelope, *soap_body, *authn_request;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(request_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	doc = xmlParseMemory(request_msg, strlen(request_msg));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "lib", LASSO_LIB_HREF);
	/* TODO: will need to use another href for id-ff 1.1 support */
	xpathObj = xmlXPathEvalExpression("//lib:AuthnRequest", xpathCtx);

	if (xpathObj == NULL)
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);

	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	authn_request = xmlCopyNode(xpathObj->nodesetval->nodeTab[0], 1);
	xmlFreeDoc(doc);

	soap_envelope = xmlNewNode(NULL, "Envelope");
	xmlSetNs(soap_envelope,
			xmlNewNs(soap_envelope, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX));

	soap_body = xmlNewTextChild(soap_envelope, NULL, "Body", NULL);
	xmlAddChild(soap_body, authn_request);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, soap_envelope, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	LASSO_PROFILE(lecp)->msg_body = g_strdup(
			buf->conv ? buf->conv->content : buf->buffer->content);
	xmlOutputBufferClose(buf);
	xmlFreeNode(soap_envelope);


	return 0;
}


/**
 * lasso_lecp_process_authn_response_envelope_msg:
 * @lecp: a #LassoLecp
 * @response_msg: the enveloped authentication response received
 *
 * Processes received enveloped authentication response, extracts the
 * authentication response out of it and stores it in @response.
 * 
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp, const char *response_msg)
{
	LassoProfile *profile;
	LassoMessageFormat format;

	g_return_val_if_fail(LASSO_IS_LECP(lecp), -1);
	g_return_val_if_fail(response_msg!=NULL, -2);

	profile = LASSO_PROFILE(lecp);

	lecp->authnResponseEnvelope = lasso_lib_authn_response_envelope_new(NULL, NULL);
	format = lasso_node_init_from_message(LASSO_NODE(lecp->authnResponseEnvelope),
			response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_MSG);
	}

	profile->response = g_object_ref(lecp->authnResponseEnvelope->AuthnResponse);
	if (profile->response == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "AuthnResponse not found");
		return LASSO_ERROR_UNDEFINED;
	}

	lecp->assertionConsumerServiceURL = g_strdup(
			lecp->authnResponseEnvelope->AssertionConsumerServiceURL);
	if (lecp->assertionConsumerServiceURL == NULL){
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	return 0;
}

/**
 * lasso_lecp_destroy:
 * @lecp: a #LassoLecp
 *
 * Destroys a #LassoLecp object
 * 
 **/
void
lasso_lecp_destroy(LassoLecp *lecp)
{
	g_object_unref(G_OBJECT(lecp));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
finalize(GObject *object)
{  
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLecp *lecp)
{
	lecp->authnRequestEnvelope = NULL;
	lecp->authnResponseEnvelope = NULL;
	lecp->assertionConsumerServiceURL = NULL;
}

static void
class_init(LassoLecpClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_lecp_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLecpClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLecp),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_LOGIN,
				"LassoLecp", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_lecp_new
 * @server: the #LassoServer
 *
 * Creates a new #LassoLecp.
 *
 * Return value: a newly created #LassoLecp object; or NULL if an error
 *     occured
 **/
LassoLecp*
lasso_lecp_new(LassoServer *server)
{
	LassoLecp *lecp;

	lecp = g_object_new(LASSO_TYPE_LECP, NULL);
	LASSO_PROFILE(lecp)->server = g_object_ref(server);

	return lecp;
}
