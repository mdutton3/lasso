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

#include <lasso/id-wsf/wsf_profile.h>
#include <lasso/xml/disco_modify.h>
#include <lasso/xml/soap_fault.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/wsse_security.h>
#include <lasso/xml/saml_assertion.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/providerprivate.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

struct _LassoWsfProfilePrivate
{
	gboolean dispose_has_run;
	LassoDiscoDescription *description;
	LassoSoapFault *fault;
};

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

LassoDiscoDescription*
lasso_wsf_profile_get_description_auto(LassoDiscoServiceInstance *si, const gchar *security_mech_id)
{
	GList *iter, *iter2;
	LassoDiscoDescription *description;

	if (security_mech_id == NULL)
		return NULL;

	iter = si->Description;
	while (iter) {
		description = LASSO_DISCO_DESCRIPTION(iter->data);
		iter2 = description->SecurityMechID;
		while (iter2) {
			if (strcmp(security_mech_id, iter->data) == 0)
				return description;
			iter2 = iter2->next;
		}
		iter = iter->next;
	}

	return NULL;
}

LassoSoapFault*
lasso_wsf_profile_get_fault(LassoWsfProfile *profile)
{
	return profile->private_data->fault;
}

gboolean
lasso_wsf_profile_has_x509_authentication(LassoWsfProfile *profile)
{
	GList *iter;
	gchar *security_mech_id;

	if (!profile->private_data->description)
		return FALSE;

	iter = profile->private_data->description->SecurityMechID;
	while(iter) {
		security_mech_id = iter->data;
		if (strcmp(security_mech_id, LASSO_SECURITY_MECH_X509) == 0 || \
		    strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_X509) == 0 || \
		    strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_X509) == 0) {
			    return TRUE;
			    break;
		}
		iter = iter->next;
	}

	return FALSE;
}

gboolean
lasso_security_mech_id_is_saml_authentication(const gchar *security_mech_id)
{
	if (!security_mech_id)
		return FALSE;

	if (strcmp(security_mech_id, LASSO_SECURITY_MECH_SAML) == 0 || \
		strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_SAML) == 0 || \
		strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_SAML) == 0)
		return TRUE;

	return FALSE;
}

void lasso_wsf_profile_set_description(LassoWsfProfile *profile, LassoDiscoDescription *description)
{
	profile->private_data->description = g_object_ref(description);
}

xmlNode*
lasso_wsf_profile_add_x509_authentication(LassoWsfProfile *profile, LassoNode *envelope,
	LassoSignatureMethod sign_method)
{
	xmlNode *envelope_node, *signature = NULL, *sign_tmpl, *reference, *key_info, *t;
	xmlNode *header = NULL, *provider = NULL, *correlation = NULL, *security = NULL;
	xmlNode *body = NULL;
	xmlSecDSigCtx *dsigCtx;
	xmlDoc *doc;
	xmlChar *id;
	char *uri;
	
	xmlAttr *id_attr;

	LassoSignatureType sign_type = LASSO_SIGNATURE_TYPE_WITHX509;

	envelope_node = lasso_node_get_xmlNode(envelope, 1);

	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, envelope_node);

	/* Get correlation, body and security elements */
	t = envelope_node->children;
	while (t) {
		if (strcmp((char *) t->name, "Header") == 0)
			header = t;
		else if (strcmp((char *) t->name, "Body") == 0)
			body = t;
		t = t->next;
	}
	if (header == NULL)
		return NULL;
	if (body == NULL)
		return NULL;

	t = header->children;
	while (t) {
		if (strcmp((char *) t->name, "Correlation") == 0)
			correlation = t;
		else if (strcmp((char *) t->name, "Provider") == 0)
			provider = t;
		else if (strcmp((char *) t->name, "Security") == 0)
			security = t;
		t = t->next;
	}
	if (correlation == NULL)
		return NULL;
	if (security == NULL)
		return NULL;

	/* Add signature template */
	if (sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1) {
		signature = xmlSecTmplSignatureCreate(NULL,
				xmlSecTransformExclC14NId,
				xmlSecTransformRsaSha1Id, NULL);
	} else {
		signature = xmlSecTmplSignatureCreate(NULL,
				xmlSecTransformExclC14NId,
				xmlSecTransformDsaSha1Id, NULL);
	}
	
	xmlAddChild(security, signature);

	/* Add reference of child element */
	/* Correlation */
	id = xmlGetProp(correlation, (xmlChar *) "id");
	uri = g_strdup_printf("#%s", id);
	reference = xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha1Id,
						    NULL, (xmlChar *)uri, NULL);
	xmlFree(uri);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
	id_attr = xmlHasProp(correlation, (xmlChar *)"id");
	xmlAddID(NULL, doc, (xmlChar *)id, id_attr);
	xmlFree(id);

	/* Body */
	id = xmlGetProp(body, (xmlChar *) "id");
	uri = g_strdup_printf("#%s", id);
	reference = xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha1Id,
						    NULL, (xmlChar *)uri, NULL);
	xmlFree(uri);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
	id_attr = xmlHasProp(body, (xmlChar *)"id");
	xmlAddID(NULL, doc, (xmlChar *)id, id_attr);
	xmlFree(id);

	/* Provider */
	if (provider) {
		uri = g_strdup_printf("#%s", xmlGetProp(provider, (xmlChar *) "id"));
		reference = xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha1Id,
							    NULL, (xmlChar*)uri, NULL);
		xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
		xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
		id_attr = xmlHasProp(provider, (xmlChar *)"id");
		xmlAddID(NULL, doc, xmlGetProp(provider, (xmlChar *) "id"), id_attr);
	}

	/* FIXME: X509 authentication needs X509 signature type */
	if (profile->server->certificate != NULL && profile->server->certificate[0] != 0) {
		key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
		xmlSecTmplKeyInfoAddX509Data(key_info);
	}

	/* Sign SOAP message */
	sign_tmpl = xmlSecFindNode(security, xmlSecNodeSignature, xmlSecDSigNs);
	if (sign_tmpl == NULL)
		return NULL;

	dsigCtx = xmlSecDSigCtxCreate(NULL);
	dsigCtx->signKey = xmlSecCryptoAppKeyLoad(profile->server->private_key,
		xmlSecKeyDataFormatPem, NULL, NULL, NULL);
	if (dsigCtx->signKey == NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return NULL;
	}
	if (profile->server->certificate != NULL && profile->server->certificate[0] != 0) {
		if (xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, profile->server->certificate,
			xmlSecKeyDataFormatPem) < 0) {
				xmlSecDSigCtxDestroy(dsigCtx);
				return NULL;
		}
	}
	if (xmlSecDSigCtxSign(dsigCtx, sign_tmpl) < 0) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return NULL;
	}
	xmlSecDSigCtxDestroy(dsigCtx);

	return envelope_node;
}

gint
lasso_wsf_profile_verify_x509_authentication(LassoWsfProfile *profile, xmlDoc *doc)
{
	LassoProvider *lasso_provider;

	xmlNode *provider, *correlation, *security, *body, *signature, *x509data, *node;
	xmlChar *id;
	xmlAttr *id_attr;

	xmlSecKeysMngr *keys_mngr = NULL;
	xmlSecDSigCtx *dsigCtx;

	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj;

	xpathCtx = xmlXPathNewContext(doc);

	/* Correlation */
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"sb", (xmlChar*)LASSO_SOAP_BINDING_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//sb:Correlation", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		correlation = xpathObj->nodesetval->nodeTab[0];
	}
	if (!correlation)
		return -1;
	id_attr = xmlHasProp(correlation, (xmlChar *)"id");
	id = xmlGetProp(correlation, (xmlChar *) "id");
	xmlAddID(NULL, doc, id, id_attr);
	xmlFree(id);

	/* Body */
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		body = xpathObj->nodesetval->nodeTab[0];
	}
	if (!body)
		return -1;
	id_attr = xmlHasProp(body, (xmlChar *)"id");
	id = xmlGetProp(body, (xmlChar *) "id");
	xmlAddID(NULL, doc, id, id_attr);
	xmlFree(id);

	/* <Provider> */
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"sb", (xmlChar*)LASSO_SOAP_BINDING_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//sb:Provider", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		provider = xpathObj->nodesetval->nodeTab[0];
	}
	if (provider) {
		char *providerID;
		id_attr = xmlHasProp(provider, (xmlChar *)"id");
		id = xmlGetProp(provider, (xmlChar *) "id");
		xmlAddID(NULL, doc, id, id_attr);
		xmlFree(id);

		providerID = (char *) xmlGetProp(provider, (xmlChar *) "providerID");
		lasso_provider = lasso_server_get_provider(profile->server, providerID);
		xmlFree(providerID);
	}

	/* Verify signature */
	node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
	if(node == NULL)
		return LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;

	x509data = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeX509Data, xmlSecDSigNs);
	if (x509data != NULL && lasso_provider->ca_cert_chain != NULL) {
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
				lasso_provider->ca_cert_chain);
		if (keys_mngr == NULL) {
			xmlFreeDoc(doc);
			return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
		}
	}

	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);
	if (keys_mngr == NULL) {
		dsigCtx->signKey = lasso_provider_get_public_key(lasso_provider);
		if (dsigCtx->signKey == NULL) {
			xmlSecDSigCtxDestroy(dsigCtx);
			xmlFreeDoc(doc);
			return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
		}
	}
	
	if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
		xmlSecDSigCtxDestroy(dsigCtx);
		if (keys_mngr)
			xmlSecKeysMngrDestroy(keys_mngr);
		return LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
	}

	if (keys_mngr)
		xmlSecKeysMngrDestroy(keys_mngr);

	if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return LASSO_DS_ERROR_INVALID_SIGNATURE;
	}
	printf("Signature is OK\n");

	return 0;
}

gint
lasso_wsf_profile_add_saml_authentication(LassoWsfProfile *profile,
	LassoSamlAssertion *credential)
{
	LassoSoapHeader *header;
	LassoWsseSecurity *security;
	GList *iter;

	security = lasso_wsse_security_new();
	security->any = g_list_append(security->any, credential);
	header = profile->soap_envelope_request->Header;
	header->Other = g_list_append(header->Other, security);

	return 0;
}

gint
lasso_wsf_profile_verify_saml_authentication(LassoWsfProfile *profile)
{
	LassoSoapHeader *header;
	LassoWsseSecurity *security = NULL;
	LassoSamlAssertion *credential;
	GList *iter;
	
	header = profile->soap_envelope_request->Header;

	/* Security */
	iter = header->Other;
	while (iter) {
		if (LASSO_IS_WSSE_SECURITY(iter->data) == TRUE) {
			security = LASSO_WSSE_SECURITY(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (!security)
		return -1;
	
	/* Assertion */
	iter = security->any;
	while (iter) {
		if (LASSO_IS_SAML_ASSERTION(iter->data) == TRUE) {
			credential = LASSO_SAML_ASSERTION(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (!credential)
		return -1;
	
	return 0;
}

LassoSoapEnvelope*
lasso_wsf_profile_build_soap_envelope(const char *refToMessageId, const char *providerId)
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

/**
 * lasso_wsf_profile_get_identity:
 * @profile: a #LassoWsfProfile
 *
 * Gets the identity bound to @profile.
 *
 * Return value: the identity or NULL if it none was found.  The #LassoIdentity
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoIdentity*
lasso_wsf_profile_get_identity(LassoWsfProfile *profile)
{
	if (profile->identity && g_hash_table_size(profile->identity->federations))
		return profile->identity;
	return NULL;
}


/**
 * lasso_wsf_profile_get_session:
 * @profile: a #LassoWsfProfile
 *
 * Gets the session bound to @profile.
 *
 * Return value: the session or NULL if it none was found.  The #LassoSession
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoSession*
lasso_wsf_profile_get_session(LassoWsfProfile *profile)
{
	if (profile->session == NULL)
		return NULL;

	if (lasso_session_is_empty(profile->session))
		return NULL;

	return profile->session;
}


/**
 * lasso_wsf_profile_is_identity_dirty:
 * @profile: a #LassoWsfProfile
 *
 * Checks whether identity has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if identity has changed
 **/
gboolean
lasso_wsf_profile_is_identity_dirty(LassoWsfProfile *profile)
{
	return (profile->identity && profile->identity->is_dirty);
}


/**
 * lasso_wsf_profile_is_session_dirty:
 * @profile: a #LassoWsfProfile
 *
 * Checks whether session has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if session has changed
 **/
gboolean
lasso_wsf_profile_is_session_dirty(LassoWsfProfile *profile)
{
	return (profile->session && profile->session->is_dirty);
}


/**
 * lasso_wsf_profile_set_identity_from_dump:
 * @profile: a #LassoWsfProfile
 * @dump: XML identity dump
 *
 * Builds a new #LassoIdentity object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_wsf_profile_set_identity_from_dump(LassoWsfProfile *profile, const gchar *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->identity = lasso_identity_new_from_dump(dump);
	if (profile->identity == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP);

	return 0;
}


/**
 * lasso_wsf_profile_set_session_from_dump:
 * @profile: a #LassoWsfProfile
 * @dump: XML session dump
 *
 * Builds a new #LassoSession object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_wsf_profile_set_session_from_dump(LassoWsfProfile *profile, const gchar  *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->session = lasso_session_new_from_dump(dump);
	if (profile->session == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_SESSION_DUMP);
	profile->session->is_dirty = FALSE;

	return 0;
}



gint
lasso_wsf_profile_init_soap_request(LassoWsfProfile *profile, LassoNode *request)
{
	LassoSoapEnvelope *envelope;

	envelope = lasso_wsf_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_WSF_PROFILE(profile)->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, request);

	return 0;
}

gint
lasso_wsf_profile_build_soap_request_msg(LassoWsfProfile *profile)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoWsseSecurity *security;
	xmlNode *xmlnode = NULL;
	char *ret;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	envelope = profile->soap_envelope_request;

	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		security = lasso_wsse_security_new();
		header = envelope->Header;
		header->Other = g_list_append(header->Other, security);
		xmlnode = lasso_wsf_profile_add_x509_authentication(profile, LASSO_NODE(envelope),
			LASSO_SIGNATURE_METHOD_RSA_SHA1);
	}

	/* dump soap request */
	if (xmlnode == NULL)
		xmlnode = lasso_node_get_xmlNode(LASSO_NODE(envelope), FALSE);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);
	xmlFreeNode(xmlnode);

	return 0;
}

gint
lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *profile)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoWsseSecurity *security;

	xmlNode *xmlnode = NULL;
	char *ret;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	envelope = profile->soap_envelope_response;

	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		security = lasso_wsse_security_new();
		header = envelope->Header;
		header->Other = g_list_append(header->Other, security);

		xmlnode = lasso_wsf_profile_add_x509_authentication(profile,
			LASSO_NODE(envelope), LASSO_SIGNATURE_METHOD_RSA_SHA1);
	}

	/* dump soap request */
	if (xmlnode == NULL)
		xmlnode = lasso_node_get_xmlNode(LASSO_NODE(envelope), TRUE);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);
	xmlFreeNode(xmlnode);

	return 0;
}

gint
lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile, const gchar *message,
					   const gchar *service_type, const gchar *security_mech_id)
{
	LassoDiscoServiceInstance *si;
	LassoSoapBindingCorrelation *correlation;
	LassoSoapEnvelope *envelope = NULL;
	LassoSoapFault *fault = NULL;
	GList *iter;
	gchar *messageId;
	int res = 0;
	xmlDoc *doc;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	si = lasso_server_get_service(profile->server, (char *) service_type);

	if (!security_mech_id) {
		if (si)
			profile->private_data->description = LASSO_DISCO_DESCRIPTION(
				si->Description->data);
		else
			profile->private_data->description = NULL;
	} else
		if (!si)
			return -1;
		else
			lasso_wsf_profile_get_description_auto(si, security_mech_id);	

	doc = xmlParseMemory(message, strlen(message));

	/* If X509 authentication mecanism, then verify signature */
	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE)
		res = lasso_wsf_profile_verify_x509_authentication(profile, doc);
	if (res > 0) {
		fault = lasso_soap_fault_new();
		fault->faultstring = "Invalid signature";
	}

	/* FIXME: Remove Signature element if exists, it seg fault when a call to
			  lasso_node_new_from_xmlNode() */
	{
		xmlNode *xmlnode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature,
			xmlSecDSigNs);
		if (xmlnode) {
			xmlUnlinkNode(xmlnode);
			xmlFreeNode(xmlnode);
		}
	}

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	profile->soap_envelope_request = envelope;
	profile->request = LASSO_NODE(envelope->Body->any->data);
	correlation = LASSO_SOAP_BINDING_CORRELATION(envelope->Header->Other->data);
	messageId = correlation->messageID;
	envelope = lasso_wsf_profile_build_soap_envelope(messageId,
		LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_WSF_PROFILE(profile)->soap_envelope_response = envelope;

	if (fault) {
		envelope->Body->any = g_list_append(envelope->Body->any, fault);
		profile->private_data->fault = fault;
	}
		
	return res;
}

gint
lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	xmlDoc *doc = xmlParseMemory(message, strlen(message));
	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		int res = lasso_wsf_profile_verify_x509_authentication(profile, doc);
		if (res != 0)
			return res;
	}
	/* FIXME: Remove Signature element if exists, it seg fault when a call to
			  lasso_node_new_from_xmlNode() */
	{
		xmlNode *xmlnode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature,
								xmlSecDSigNs);
		if (xmlnode) {
			xmlUnlinkNode(xmlnode);
			xmlFreeNode(xmlnode);
		}
	}

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));

	profile->soap_envelope_response = envelope;
	
	/* Soap Fault message */
	if (LASSO_IS_SOAP_FAULT(envelope->Body->any->data) == TRUE)
		return -1;
	
	/* Soap Body message */
	profile->response = LASSO_NODE(envelope->Body->any->data);

	return 0;
}

LassoSoapBindingProvider *lasso_wsf_profile_set_provider_soap_request(LassoWsfProfile *profile,
	const char *providerId)
{
	LassoSoapBindingProvider *provider;
	LassoSoapEnvelope *soap_request;
	LassoSoapHeader *header;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), NULL);
	g_return_val_if_fail(providerId != NULL, NULL);

	soap_request = profile->soap_envelope_request;
	g_return_val_if_fail(LASSO_IS_SOAP_ENVELOPE(soap_request) == TRUE, NULL);

	header = profile->soap_envelope_request->Header;
	provider = lasso_soap_binding_provider_new(providerId);
	header->Other = g_list_append(header->Other, provider);

	return provider;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);

	if (profile->private_data->dispose_has_run == TRUE)
		return;
	profile->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);
	g_free(profile->private_data);
	profile->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsfProfile *profile)
{
	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->soap_envelope_request = NULL;
	profile->soap_envelope_response = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
	
	profile->private_data = g_new0(LassoWsfProfilePrivate, 1);
	profile->private_data->dispose_has_run = FALSE;
	profile->private_data->description = NULL;
	profile->private_data->fault = NULL;
}

static void
class_init(LassoWsfProfileClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_wsf_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoWsfProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsfProfile),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsfProfile", &this_info, 0);
	}
	return this_type;
}

LassoWsfProfile*
lasso_wsf_profile_new(LassoServer *server)
{
	LassoWsfProfile *profile = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	profile = g_object_new(LASSO_TYPE_WSF_PROFILE, NULL);

	return profile;
}
