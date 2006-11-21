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

#include <lasso/saml-2.0/ecp.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_ecp_destroy:
 * @ecp: a #LassoEcp
 *
 * Destroys a #LassoEcp object
 * 
 **/
void
lasso_ecp_destroy(LassoEcp *ecp)
{
	g_object_unref(G_OBJECT(ecp));
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
instance_init(LassoEcp *ecp)
{
	ecp->assertionConsumerURL = NULL;
}

static void
class_init(LassoEcpClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

int
lasso_ecp_process_authn_request_msg(LassoEcp *ecp, const char *authn_request_msg)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *xmlnode;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	if (authn_request_msg == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_MISSING_REQUEST);
	}
	doc = xmlParseMemory(authn_request_msg, strlen(authn_request_msg));
	xpathCtx = xmlXPathNewContext(doc);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"ecp", (xmlChar*)LASSO_ECP_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ecp:RelayState", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		xmlnode = xpathObj->nodesetval->nodeTab[0];
		LASSO_PROFILE(ecp)->msg_relayState = (char*)xmlNodeGetContent(xmlnode);
	}

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Header", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		xmlnode = xpathObj->nodesetval->nodeTab[0];
		xmlUnlinkNode(xmlnode);
	}

	xmlnode = xmlDocGetRootElement(doc);
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	LASSO_PROFILE(ecp)->msg_body = \
		g_strdup((char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);

	return 0;
}

int
lasso_ecp_process_response_msg(LassoEcp *ecp, const char *response_msg)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *envelope, *new_envelope, *header, *paos_response, *ecp_relay_state;
	xmlNode *body = NULL;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	xmlNs *soap_env_ns, *ecp_ns;

	doc = xmlParseMemory(response_msg, strlen(response_msg));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		body = xpathObj->nodesetval->nodeTab[0];
	}

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"ecp", (xmlChar*)LASSO_ECP_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ecp:Response", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		ecp->assertionConsumerURL = (char*)xmlGetProp(
			xpathObj->nodesetval->nodeTab[0], (xmlChar*)"AssertionConsumerURL");
	}

	xmlXPathFreeContext(xpathCtx);
	xmlXPathFreeObject(xpathObj);

	new_envelope = xmlNewNode(NULL, (xmlChar*)"Envelope");
	xmlSetNs(new_envelope, xmlNewNs(new_envelope,
		(xmlChar*)LASSO_SOAP_ENV_HREF, (xmlChar*)LASSO_SOAP_ENV_PREFIX));
	xmlNewNs(paos_response,
		(xmlChar*)LASSO_PAOS_HREF, (xmlChar*)LASSO_PAOS_PREFIX);
	xmlNewNs(new_envelope,
		(xmlChar*)LASSO_SAML_ASSERTION_HREF, (xmlChar*)LASSO_SAML_ASSERTION_PREFIX);
	header = xmlNewTextChild(new_envelope, NULL, (xmlChar*)"Header", NULL);

	/* PAOS request header block */
	soap_env_ns = xmlNewNs(envelope,
				(xmlChar*)LASSO_SOAP_ENV_HREF, (xmlChar*)LASSO_SOAP_ENV_PREFIX);
	paos_response = xmlNewNode(NULL, (xmlChar*)"Response");
	xmlSetNs(paos_response, xmlNewNs(paos_response,
				(xmlChar*)LASSO_PAOS_HREF, (xmlChar*)LASSO_PAOS_PREFIX));
	xmlSetNsProp(paos_response, soap_env_ns, (xmlChar*)"mustUnderstand", (xmlChar*)"1");
	xmlSetNsProp(paos_response, soap_env_ns, (xmlChar*)"actor",
				(xmlChar*)LASSO_SOAP_ENV_ACTOR);
	xmlAddChild(header, paos_response);

	/* ECP relay state block */
	if (LASSO_PROFILE(ecp)->msg_relayState) {
		ecp_relay_state = xmlNewNode(NULL, (xmlChar*)"RelayState");
		xmlNodeSetContent(ecp_relay_state, (xmlChar*)LASSO_PROFILE(ecp)->msg_relayState);
		ecp_ns = xmlNewNs(ecp_relay_state, (xmlChar*)LASSO_ECP_HREF,
					(xmlChar*)LASSO_ECP_PREFIX);
		xmlSetNs(ecp_relay_state, ecp_ns);
		xmlSetNsProp(ecp_relay_state, soap_env_ns, (xmlChar*)"mustUnderstand",
					(xmlChar*)"1");
		xmlSetNsProp(ecp_relay_state, soap_env_ns, (xmlChar*)"actor",
					(xmlChar*)LASSO_SOAP_ENV_ACTOR);
		xmlAddChild(header, ecp_relay_state);
	}

	xmlAddChild(new_envelope, xmlCopyNode(body, 1));

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, new_envelope, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	LASSO_PROFILE(ecp)->msg_body = \
		g_strdup((char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);

	xmlFreeDoc(doc);

	return 0;
}

GType
lasso_ecp_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoEcpClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoEcp),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoEcp", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_ecp_new
 *
 * Creates a new #LassoEcp.
 *
 * Return value: a newly created #LassoEcp object; or NULL if an error
 *     occured
 **/
LassoEcp*
lasso_ecp_new()
{
	LassoEcp *ecp;

	ecp = g_object_new(LASSO_TYPE_ECP, NULL);

	return ecp;
}
