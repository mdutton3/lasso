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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * SECTION:ecp
 * @short_description: Enhanced Client or Proxy Profile (SAMLv2)
 *
 **/

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "providerprivate.h"
#include "profileprivate.h"
#include "../id-ff/providerprivate.h"
#include "../id-ff/identityprivate.h"
#include "../id-ff/serverprivate.h"

#include "ecpprivate.h"

#include "ecp.h"
#include "../utils.h"

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
	lasso_node_destroy(LASSO_NODE(ecp));
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoEcp *ecp = LASSO_ECP(object);

	if (ecp->private_data->messageID) {
		xmlFree(ecp->private_data->messageID);
		ecp->private_data->messageID = NULL;
	}

	if (ecp->private_data->relay_state) {
		xmlFree(ecp->private_data->relay_state);
		ecp->private_data->relay_state = NULL;
	}

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(ecp));
}

static void
finalize(GObject *object)
{
	LassoEcp *ecp = LASSO_ECP(object);
	lasso_release(ecp->private_data);
	ecp->private_data = NULL;

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoEcp *ecp)
{
	ecp->private_data = g_new0(LassoEcpPrivate, 1);
	ecp->private_data->messageID = NULL;
	ecp->private_data->relay_state = NULL;

	ecp->assertionConsumerURL = NULL;
}

static void
class_init(LassoEcpClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);
	parent_class = g_type_class_peek_parent(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Ecp");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

int
lasso_ecp_process_authn_request_msg(LassoEcp *ecp, const char *authn_request_msg)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *xmlnode;
	LassoProfile *profile;
	LassoProvider *remote_provider;

	g_return_val_if_fail(LASSO_IS_ECP(ecp), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(authn_request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(ecp);

	doc = lasso_xml_parse_memory(authn_request_msg, strlen(authn_request_msg));
	xpathCtx = xmlXPathNewContext(doc);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"ecp", (xmlChar*)LASSO_ECP_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ecp:RelayState", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		xmlnode = xpathObj->nodesetval->nodeTab[0];
		ecp->private_data->relay_state = xmlNodeGetContent(xmlnode);
	}
	xmlXPathFreeObject(xpathObj);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"paos", (xmlChar*)LASSO_PAOS_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//paos:Request", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		ecp->private_data->messageID = xmlGetProp(
			xpathObj->nodesetval->nodeTab[0], (xmlChar*)"messageID");
	}
	xmlXPathFreeObject(xpathObj);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Header", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		xmlnode = xpathObj->nodesetval->nodeTab[0];
		xmlUnlinkNode(xmlnode);
		xmlFreeNode(xmlnode);
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	xpathCtx = NULL;
	xpathObj = NULL;

	xmlnode = xmlDocGetRootElement(doc);
	lasso_assign_new_string(LASSO_PROFILE(ecp)->msg_body,
			lasso_xmlnode_to_string(xmlnode, 0, 0))
	lasso_release_doc(doc);

	profile->remote_providerID = lasso_server_get_first_providerID_by_role(profile->server, LASSO_PROVIDER_ROLE_IDP);
	if (profile->remote_providerID == NULL) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	remote_provider = lasso_server_get_provider(profile->server, profile->remote_providerID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		return critical_error(LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND);
	}

	profile->msg_url = lasso_provider_get_metadata_one(remote_provider,
				"SingleSignOnService SOAP");
	if (profile->msg_url == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL);
	}

	return 0;
}

int
lasso_ecp_process_response_msg(LassoEcp *ecp, const char *response_msg)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *new_envelope, *header, *paos_response, *ecp_relay_state;
	xmlNode *body = NULL;
	xmlNs *soap_env_ns, *ecp_ns;

	g_return_val_if_fail(LASSO_IS_ECP(ecp), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	doc = lasso_xml_parse_memory(response_msg, strlen(response_msg));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		body = xmlCopyNode(xpathObj->nodesetval->nodeTab[0], 1);
	}
	xmlXPathFreeObject(xpathObj);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"ecp", (xmlChar*)LASSO_ECP_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ecp:Response", xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		ecp->assertionConsumerURL = (char*)xmlGetProp(
			xpathObj->nodesetval->nodeTab[0], (xmlChar*)"AssertionConsumerURL");
	}
	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);
	xpathCtx = NULL;
	xpathObj = NULL;

	new_envelope = xmlNewNode(NULL, (xmlChar*)"Envelope");
	xmlSetNs(new_envelope, xmlNewNs(new_envelope,
		(xmlChar*)LASSO_SOAP_ENV_HREF, (xmlChar*)LASSO_SOAP_ENV_PREFIX));
	xmlNewNs(new_envelope,
		(xmlChar*)LASSO_SAML_ASSERTION_HREF, (xmlChar*)LASSO_SAML_ASSERTION_PREFIX);
	header = xmlNewTextChild(new_envelope, NULL, (xmlChar*)"Header", NULL);

	/* PAOS request header block */
	soap_env_ns = xmlNewNs(new_envelope,
				(xmlChar*)LASSO_SOAP_ENV_HREF, (xmlChar*)LASSO_SOAP_ENV_PREFIX);
	paos_response = xmlNewNode(NULL, (xmlChar*)"Response");
	xmlSetNs(paos_response, xmlNewNs(paos_response,
				(xmlChar*)LASSO_PAOS_HREF, (xmlChar*)LASSO_PAOS_PREFIX));
	xmlSetNsProp(paos_response, soap_env_ns, (xmlChar*)"mustUnderstand", (xmlChar*)"1");
	xmlSetNsProp(paos_response, soap_env_ns, (xmlChar*)"actor",
				(xmlChar*)LASSO_SOAP_ENV_ACTOR);
	if (ecp->private_data->messageID) {
		xmlSetNsProp(paos_response, soap_env_ns, (xmlChar*)"refToMessageID",
			(xmlChar*)ecp->private_data->messageID);
	}
	xmlAddChild(header, paos_response);

	/* ECP relay state block */
	if (ecp->private_data->relay_state) {
		ecp_relay_state = xmlNewNode(NULL, (xmlChar*)"RelayState");
		xmlNodeSetContent(ecp_relay_state, (xmlChar*)ecp->private_data->relay_state);
		ecp_ns = xmlNewNs(ecp_relay_state, (xmlChar*)LASSO_ECP_HREF,
					(xmlChar*)LASSO_ECP_PREFIX);
		xmlSetNs(ecp_relay_state, ecp_ns);
		xmlSetNsProp(ecp_relay_state, soap_env_ns, (xmlChar*)"mustUnderstand",
					(xmlChar*)"1");
		xmlSetNsProp(ecp_relay_state, soap_env_ns, (xmlChar*)"actor",
					(xmlChar*)LASSO_SOAP_ENV_ACTOR);
		xmlAddChild(header, ecp_relay_state);
	}

	xmlAddChild(new_envelope, body);
	lasso_assign_new_string(LASSO_PROFILE(ecp)->msg_body,
			lasso_xmlnode_to_string(new_envelope, 0, 0))
	lasso_release_doc(doc);
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
			NULL
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
lasso_ecp_new(LassoServer *server)
{
	LassoEcp *ecp;

	ecp = g_object_new(LASSO_TYPE_ECP, NULL);
	LASSO_PROFILE(ecp)->server = g_object_ref(server);

	return ecp;
}
