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

#include <lasso/id-wsf/authentication.h>
#include <lasso/xml/sa_sasl_request.h>
#include <lasso/xml/sa_sasl_response.h>
#include <lasso/xml/soap_body.h>
#include <lasso/xml/soap_header.h>
#include <lasso/xml/soap_binding_correlation.h>

struct _LassoAuthenticationPrivate
{
	gboolean dispose_has_run;
};

gint
lasso_authentication_client_start(LassoAuthentication *authentication)
{
	LassoSaSASLRequest *request;
	int res;
	const char *mechusing;
	const char *out;
	int outlen = 0;

	xmlChar *outbase64;

	/* Liberty part */
	request = LASSO_SA_SASL_REQUEST(LASSO_WSF_PROFILE(authentication)->request);

	/* sasl part */
	res = sasl_client_start(authentication->connection, /* same context from above */
				request->mechanism, /* list of mechanisms from the server */
				NULL, /* filled in if an interaction is needed */
				&out, /* filled in on success */
				&outlen, /* filled in on success */
				&mechusing);

	/* mechusing is th resulting best mech to use, so copy it in SASLRequest element */
	if (mechusing != NULL) {
		g_free(request->mechanism);
		request->mechanism = g_strdup(mechusing);
	}
       
	if (outlen > 0) {
		outbase64 = xmlSecBase64Encode(out, outlen, 0);
		request->Data = g_list_append(request->Data, outbase64);
	}

	return res;
}

gint
lasso_authentication_client_step(LassoAuthentication *authentication)
{
	LassoSaSASLRequest *request;
	LassoSaSASLResponse *response;
	int res;
	char *in = NULL;
	int inlen = 0;
	xmlChar *inbase64 = NULL;

	xmlChar *outbase64;
	const char *out;
	int outlen = 0;

	/* Liberty part */
	request = LASSO_SA_SASL_REQUEST(LASSO_WSF_PROFILE(authentication)->request);
	response = LASSO_SA_SASL_RESPONSE(LASSO_WSF_PROFILE(authentication)->response);

	/* sasl part */
	if (response->Data != NULL) {
		inbase64 = response->Data->data;
		in = g_malloc(strlen(inbase64));
		xmlSecBase64Decode(inbase64, in, strlen(inbase64));
	}

	res = sasl_client_step(authentication->connection, /* our context */
			       in,    /* the data from the server */
			       inlen, /* it's length */
			       NULL,  /* this should be unallocated and NULL */
			       &out,     /* filled in on success */
			       &outlen); /* filled in on success */

	if (strlen(out) > 0) {
		outbase64 = xmlSecBase64Encode(out, outlen, 0);
		request->Data = g_list_append(request->Data, outbase64);
	}

	return res;
}

void
lasso_authentication_destroy(LassoAuthentication *authentication)
{
	g_object_unref(G_OBJECT(authentication));
}

char*
lasso_authentication_get_mechanism_list(LassoAuthentication *authentication)
{
	int res;
	const char *result_string;
	int string_length = 0;
	unsigned number_of_mechanisms;

	if (authentication->connection == NULL) {
		return NULL;
	}

	res = sasl_listmech(authentication->connection,  /* The context for this connection */
			    NULL,  /* not supported */
			    "",   /* What to prepend the string with */
			    " ",  /* What to separate mechanisms with */
			    "",   /* What to append to the string */
			    &result_string, /* The produced string. */
			    &string_length, /* length of the string */
			    &number_of_mechanisms); /* Number of mechanisms in
						       the string */
	if (result_string == NULL)
		return NULL;

	return g_strdup(result_string);
}

gint
lasso_authentication_init_request(LassoAuthentication *authentication,
				  LassoDiscoDescription *description,
				  const gchar *mechanisms,
				  sasl_callback_t *callbacks)
{
	LassoSoapBody *body;
	LassoSoapHeader *header;
	LassoSoapBindingCorrelation *correlation;
	gchar *messageId, *timestamp;

	int res;

	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_DESCRIPTION(description),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(mechanisms != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* Liberty part : init request, set url SOAP end point */
	LASSO_WSF_PROFILE(authentication)->request = \
		LASSO_NODE(lasso_sa_sasl_request_new(mechanisms));

	if (description->Endpoint != NULL) {
		LASSO_WSF_PROFILE(authentication)->msg_url = g_strdup(description->Endpoint);
	}
	/* TODO: get Endpoint at WsdlURI */
	else if (description->WsdlURI != NULL) {

	}

	/* init soap envelope and add previous request */
	body = lasso_soap_body_new();
	body->Any = g_list_append(body->Any, LASSO_WSF_PROFILE(authentication)->request);
	LASSO_WSF_PROFILE(authentication)->soap_envelope_request = lasso_soap_envelope_new(body);

	/* add correlation in header */
	header = lasso_soap_header_new();
	LASSO_WSF_PROFILE(authentication)->soap_envelope_request->Header = header;

	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
	header->Other = g_list_append(header->Other, correlation);

	/* sasl client new connection */
	res = sasl_client_init(callbacks);
	if (res != SASL_OK) {
		return res;
	}

	res = sasl_client_new(LASSO_SA_SASL_SERVICE_NAME,
			      NULL,
			      NULL,
			      NULL,
			      NULL,
			      0,
			      &authentication->connection);

	return res;
}

gint
lasso_authentication_process_request_msg(LassoAuthentication *authentication,
					 const gchar *soap_msg)
{
	LassoSoapEnvelope *soap_envelope;
	LassoSaSASLRequest *request;
	LassoSaSASLResponse *response;
	LassoUtilityStatus *status;

	LassoSoapBody *body;
	LassoSoapHeader *header;
	LassoSoapBindingCorrelation *correlation;

	gchar *messageId, *timestamp;
	int res = 0;
	
	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(soap_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* process soap envelope request */
	soap_envelope = lasso_node_new_from_dump(soap_msg);
	LASSO_WSF_PROFILE(authentication)->soap_envelope_request = soap_envelope;
	LASSO_WSF_PROFILE(authentication)->request = LASSO_NODE(soap_envelope->Body->Any->data);

	/* Liberty part : init response */
	status = lasso_utility_status_new(LASSO_SA_STATUS_CODE_OK);
	response = lasso_sa_sasl_response_new(status);
	LASSO_WSF_PROFILE(authentication)->response = LASSO_NODE(response);

	/* set soap Envelope and Body */
	body = lasso_soap_body_new();
	body->Any = g_list_append(body->Any, response);
	soap_envelope = lasso_soap_envelope_new(body);
	LASSO_WSF_PROFILE(authentication)->soap_envelope_response = soap_envelope;
	
	/* add Correlation in Header */
	header = lasso_soap_header_new();
	LASSO_WSF_PROFILE(authentication)->soap_envelope_response->Header = header;
	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
	header->Other = g_list_append(header->Other, correlation);

	return res;
}

gint
lasso_authentication_process_response_msg(LassoAuthentication *authentication,
					  const gchar *soap_msg)
{
	LassoSoapEnvelope *soap_envelope;
	LassoSaSASLRequest *request;
	LassoSaSASLResponse *response;

	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(soap_msg != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	soap_envelope = lasso_node_new_from_dump(soap_msg);
	LASSO_WSF_PROFILE(authentication)->soap_envelope_response = soap_envelope;
	LASSO_WSF_PROFILE(authentication)->response = LASSO_NODE(soap_envelope->Body->Any->data);
	response = LASSO_WSF_PROFILE(authentication)->response;

	/* if continue, init another request */
	if (g_str_equal(response->Status->code, LASSO_SA_STATUS_CODE_CONTINUE) == TRUE) {
		if (LASSO_IS_SA_SASL_REQUEST(LASSO_WSF_PROFILE(authentication)->request) == TRUE) {
			lasso_node_destroy(LASSO_WSF_PROFILE(authentication)->request);
		}

		request = lasso_sa_sasl_request_new(g_strdup(response->serverMechanism));
		LASSO_WSF_PROFILE(authentication)->request = LASSO_NODE(request);
	}

	return 0;
}

gint
lasso_authentication_server_start(LassoAuthentication *authentication)
{
	LassoSaSASLRequest *request;
	LassoSaSASLResponse *response;

	int res;

	char *clientin = NULL;
	int clientinlen = 0;

	const char *out;
	int outlen = 0;
	xmlChar *outbase64;

	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* Sasl part : init sasl server connection only for the first time */
	res = sasl_server_init(NULL, "Lasso"); /* FIXME : should be a param */
	res = sasl_server_new(LASSO_SA_SASL_SERVICE_NAME,
			      NULL,
			      NULL,
			      NULL,
			      NULL,
			      NULL,
			      0,
			      &authentication->connection);

	/* Liberty part */
	request = LASSO_SA_SASL_REQUEST(LASSO_WSF_PROFILE(authentication)->request);
	response = LASSO_SA_SASL_RESPONSE(LASSO_WSF_PROFILE(authentication)->response);

	if (request->Data != NULL) {
		clientin = request->Data->data;
		clientinlen = strlen(clientin);
	}

	res = sasl_server_start(authentication->connection, /* context */
				request->mechanism,
				clientin,    /* the optional string the client gave us */
				clientinlen, /* and it's length */
				&out, /* The output of the library. Might not be NULL terminated */
				&outlen);

	/* set status code in SASLResponse message */
	if (res != SASL_OK) {
		g_free(response->Status->code);
		if (res == SASL_CONTINUE) {
			response->Status->code = g_strdup(LASSO_SA_STATUS_CODE_CONTINUE);
		}
		else {
			response->Status->code = g_strdup(LASSO_SA_STATUS_CODE_ABORT);
		}
	}

	/* Liberty part : */
	response->serverMechanism = g_strdup(request->mechanism);

	/* base64 encode out and add in Data element of SASLResponse */
	if (outlen > 0) {
		outbase64 = xmlSecBase64Encode(out, outlen, 0);
		response->Data = g_list_append(response->Data, outbase64);
	}

	return res;
}

gint
lasso_authentication_server_step(LassoAuthentication *authentication)
{
	LassoSaSASLRequest *request;
	LassoSaSASLResponse *response;

	int res;

	char *in = NULL;
	int inlen = 0;
	xmlChar *inbase64;

	const char *out;
	int outlen = 0;
	xmlChar *outbase64;
	
	g_return_val_if_fail(LASSO_IS_AUTHENTICATION(authentication),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* Liberty part */
	request = LASSO_SA_SASL_REQUEST(LASSO_WSF_PROFILE(authentication)->request);
	response = LASSO_SA_SASL_RESPONSE(LASSO_WSF_PROFILE(authentication)->response);

	if (request->Data != NULL) {
		inbase64 = request->Data->data;
		in = g_malloc(strlen(inbase64));
		xmlSecBase64Decode(inbase64, in, strlen(inbase64));
		inlen = strlen(in);
	}

	/* sasl part */
	res = sasl_server_step(authentication->connection,
			       in,      /* what the client gave */
			       inlen,   /* it's length */
			       &out,          /* Might not be NULL terminated */
			       &outlen);

	if (res != SASL_OK) {
		g_free(response->Status->code);
		if (res == SASL_CONTINUE) {
			response->Status->code = g_strdup(LASSO_SA_STATUS_CODE_ABORT);
		}
		else  {
			response->Status->code = g_strdup(LASSO_SA_STATUS_CODE_ABORT);
		}
	}

	/* Liberty part : base64 encode out and add in Data element of SASLResponse */
	if (outlen > 0) {
		outbase64 = xmlSecBase64Encode(out, outlen, 0);
		response->Data = g_list_append(response->Data, outbase64);
	}

	/* connection must be saved in application to be restore next exchange */
	/* ref count on it */
	g_object_ref(authentication->connection);

	return res;
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
	xmlNodeSetName(xmlnode, "Authentication");
	xmlSetProp(xmlnode, "AuthenticationDumpVersion", "2");

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
	LassoAuthentication *authentication = LASSO_AUTHENTICATION(object);

	if (authentication->private_data->dispose_has_run == TRUE)
		return;
	authentication->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoAuthentication *authentication = LASSO_AUTHENTICATION(object);
	g_free(authentication->private_data);
	authentication->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoAuthentication *authentication)
{
	authentication->private_data = g_new(LassoAuthenticationPrivate, 1);
	authentication->private_data->dispose_has_run = FALSE;
}

static void
class_init(LassoAuthenticationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_authentication_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoAuthenticationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoAuthentication),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF_PROFILE,
						   "LassoAuthentication", &this_info, 0);
	}
	return this_type;
}

LassoAuthentication*
lasso_authentication_new(LassoServer *server)
{
	LassoAuthentication *authentication = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	authentication = g_object_new(LASSO_TYPE_AUTHENTICATION, NULL);
	LASSO_WSF_PROFILE(authentication)->server = server;

	return authentication;
}
