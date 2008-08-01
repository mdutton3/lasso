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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/utils.h>

#include <lasso/id-wsf/wsf_profile.h>
#include <lasso/id-wsf/wsf_profile_private.h>
#include <lasso/id-wsf/discovery.h>
#include <lasso/xml/disco_modify.h>
#include <lasso/xml/soap_fault.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/soap_binding_processing_context.h>
#include <lasso/xml/wsse_security.h>
#include <lasso/xml/saml_assertion.h>
#include <lasso/xml/saml_authentication_statement.h>
#include <lasso/xml/saml_subject_statement_abstract.h>
#include <lasso/xml/saml_subject.h>
#include <lasso/xml/ds_key_info.h>
#include <lasso/xml/ds_key_value.h>
#include <lasso/xml/ds_rsa_key_value.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/providerprivate.h>

struct _LassoWsfProfilePrivate
{
	gboolean dispose_has_run;
	LassoDiscoDescription *description;
	LassoSoapFault *fault;
	gchar *public_key;
	GList *credentials;
};

static gint lasso_wsf_profile_verify_x509_authentication(LassoWsfProfile *profile,
		xmlDoc *doc, xmlSecKey *public_key);
static gboolean lasso_wsf_profile_has_saml_authentication(LassoWsfProfile *profile);
static gboolean lasso_wsf_profile_has_x509_authentication(LassoWsfProfile *profile);
static gint lasso_wsf_profile_verify_credential_signature(
		LassoWsfProfile *profile, xmlDoc *doc, xmlNode *credential);
static gint lasso_wsf_profile_add_credential_signature(LassoWsfProfile *profile,
		xmlDoc *doc, xmlNode *credential, LassoSignatureMethod sign_method);
static xmlSecKey* lasso_wsf_profile_get_public_key_from_credential(
		LassoWsfProfile *profile, xmlNode *credential);
static gint lasso_wsf_profile_verify_saml_authentication(LassoWsfProfile *profile, xmlDoc *doc);
static gint lasso_wsf_profile_add_soap_signature(LassoWsfProfile *profile,
		xmlDoc *doc, xmlNode *envelope_node, LassoSignatureMethod sign_method);
static int lasso_wsf_profile_ensure_soap_credentials_signature(
		LassoWsfProfile *profile, xmlDoc *doc, xmlNode *soap_envelope);

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Server", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, server) },
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, request) },
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, response) },
	{ "SOAP-Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, soap_envelope_request) },
	{ "SOAP-Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, soap_envelope_response) },
	{ "MsgUrl", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsfProfile, msg_url) },
	{ "MsgBody", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsfProfile, msg_body) },
	{ "Identity", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, identity) },
	{ "Session", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, session) },
	{ NULL, 0, 0}
};

/**
 * lasso_wsf_profile_move_credentials:
 * @src: a #LassoWsfProfile containing the credentials
 * @dest: the #LassoWsfProfile where to add the credentials
 *
 * Move all credentials #xmlNode from src to dest. After this function
 * the #LassoWsfProfile src does not contain any credential.
 *
 * Returns: 0.
 */ 
gint
lasso_wsf_profile_move_credentials(LassoWsfProfile *src, LassoWsfProfile *dest)
{
	xmlNode *credential;
	GList *iter;

	iter = src->private_data->credentials;
	while (iter) {
		credential = (xmlNode *) iter->data;
		lasso_wsf_profile_add_credential(dest, credential);
		iter = iter->next;
	}

	g_list_free(src->private_data->credentials);
	src->private_data->credentials = NULL;

	return 0;
}

/** 
 * lasso_wsf_profile_add_credential:
 * @profile: a #LassoWsfProfile
 * @credential: an #xmlNode containing credential informations
 *
 * Add credential for use in a future ID-WSF request to the underlying
 * service.
 *
 * Returns: 0.
 */
gint
lasso_wsf_profile_add_credential(LassoWsfProfile *profile, xmlNode *credential)
{
	profile->private_data->credentials = g_list_append(profile->private_data->credentials,
							   credential);
	return 0;
}

/**
 * lasso_wsf_profile_set_public_key:
 * @profile: a #LassoWsfProfile
 * @public_key: a string containg an encoded public key.
 *
 * Setup a public key to validate credentials on received requests.
 */
void
lasso_wsf_profile_set_public_key(LassoWsfProfile *profile, const char *public_key)
{
	if (public_key) {
		g_assign_string(profile->private_data->public_key, public_key);
	}
}

/*
 * lasso_wsf_profile_get_description_autos:
 * @si: a #LassoDiscoServiceInstance
 * @security_mech_id: the URI of a liberty security mechanism
 *
 * Traverse the service instance descriptions and find one which supports the
 * given security mechanism.
 *
 * Returns: a #LassoDiscoDescription that supports security_mech_id, NULL
 * otherwise.
 */
static LassoDiscoDescription*
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
			if (strcmp(security_mech_id, iter2->data) == 0)
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

static gboolean
lasso_wsf_profile_has_saml_authentication(LassoWsfProfile *profile)
{
	GList *iter;
	gchar *security_mech_id;

	if (profile->private_data->description == NULL)
		return FALSE;

	iter = profile->private_data->description->SecurityMechID;
	while (iter) {
		security_mech_id = iter->data;
		if (strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_SAML) == 0 ||
				strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_SAML) == 0 ||
				strcmp(security_mech_id, LASSO_SECURITY_MECH_SAML) == 0) {
			return TRUE;
		}
		iter = g_list_next(iter);
	}

	return FALSE;
}

static gboolean
lasso_wsf_profile_has_x509_authentication(LassoWsfProfile *profile)
{
	GList *iter;
	gchar *security_mech_id;

	if (profile->private_data->description == NULL)
		return FALSE;

	iter = profile->private_data->description->SecurityMechID;
	while (iter) {
		security_mech_id = iter->data;
		if (strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_X509) == 0 ||
				strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_X509) == 0 ||
				strcmp(security_mech_id, LASSO_SECURITY_MECH_X509) == 0) {
			return TRUE;
		}
		iter = g_list_next(iter);
	}

	return FALSE;
}

gboolean
lasso_security_mech_id_is_saml_authentication(const gchar *security_mech_id)
{
	if (!security_mech_id)
		return FALSE;

	if (strcmp(security_mech_id, LASSO_SECURITY_MECH_SAML) == 0 ||
			strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_SAML) == 0 ||
			strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_SAML) == 0)
		return TRUE;

	return FALSE;
}

/**
 * lasso_wsf_profile_set_description_from_offering_with_sec_mech:
 * @profile: a #LassoWsfProfile
 * @offering: a #LassoDiscoResourceOffering containing descriptions
 * @security_mech_id: an URL representing the wished security mechanism, if NULL take the first descriptions
 *
 * Setup the LassoWsfProfile for a given security mechanism.
 *
 * Returns: 0 if a corresponding description was found,
 * LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION if no description with the
 * given security mechanism was found.
 */
gint
lasso_wsf_profile_set_description_from_offering(
	LassoWsfProfile *profile,
	LassoDiscoResourceOffering *offering,
	const gchar *security_mech_id)
{
	LassoDiscoDescription *description = NULL;

	g_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_invalid_param(DISCO_RESOURCE_OFFERING, offering,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	if (security_mech_id == NULL) {
		if (offering->ServiceInstance &&
		    offering->ServiceInstance->Description) {
			description = LASSO_DISCO_DESCRIPTION(
					offering->ServiceInstance->Description->data);
		}
	} else {
		description = lasso_discovery_get_description_auto(
				offering, security_mech_id);
	}
	if (description == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION;
	}
	lasso_wsf_profile_set_description(profile, description);
	return 0;
}

void
lasso_wsf_profile_set_description(LassoWsfProfile *profile, LassoDiscoDescription *description)
{
	g_assign_gobject(profile->private_data->description, description);
}

static gint
lasso_wsf_profile_verify_credential_signature(
		LassoWsfProfile *profile, xmlDoc *doc, xmlNode *credential)
{
	LassoProvider *lasso_provider;

	xmlSecKeysMngr *keys_mngr = NULL;
	xmlNode *x509data = NULL, *node;

	xmlChar *id;
	xmlAttr *id_attr;

	xmlSecDSigCtx *dsigCtx;

	xmlChar *issuer;

	/* Retrieve provider id of credential signer . Issuer could be the right place */
	issuer = xmlGetProp(credential, (xmlChar*)"Issuer");
	if (issuer == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_ISSUER;
	}

	lasso_provider = lasso_server_get_provider(profile->server, (char*)issuer);
	if (lasso_provider == NULL) {
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
	}

	/* Set credential reference */
	id_attr = xmlHasProp(credential, (xmlChar *)"AssertionID");
	id = xmlGetProp(credential, (xmlChar *) "AssertionID");
	xmlAddID(NULL, doc, id, id_attr);
	xmlFree(id);

	/* Case of X509 signature type */
	x509data = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeX509Data, xmlSecDSigNs);
	if (x509data != NULL && lasso_provider != NULL && lasso_provider->ca_cert_chain != NULL) {
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
				lasso_provider->ca_cert_chain);
		if (keys_mngr == NULL) {
			return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
		}
	} else if (x509data != NULL) {
		return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
	}

	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);

	/* Case of simple public key signature type */
	if (keys_mngr == NULL) {
		if (lasso_provider != NULL) {
			dsigCtx->signKey = xmlSecKeyDuplicate(
					lasso_provider_get_public_key(lasso_provider));
		} else if (profile->private_data->public_key) {
			/* TODO */
		}
		if (dsigCtx->signKey == NULL) {
			xmlSecDSigCtxDestroy(dsigCtx);
			return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
		}
	}

	node = xmlSecFindNode(credential, xmlSecNodeSignature, xmlSecDSigNs);
	if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
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

	/* Remove uneeded signature node */
	xmlUnlinkNode(node);
	xmlFreeNode(node);

	return 0;
}

static gint
lasso_wsf_profile_add_credential_signature(LassoWsfProfile *profile,
		xmlDoc *doc, xmlNode *credential, LassoSignatureMethod sign_method)
{
	xmlNode *signature = NULL, *sign_tmpl, *reference, *key_info;
	char *uri;
	
	xmlAttr *id_attr;

	xmlSecDSigCtx *dsigCtx;

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

	xmlAddChild(credential, signature);

	/* Credential reference */
	uri = g_strdup_printf("#%s", xmlGetProp(credential, (xmlChar *) "AssertionID"));
	reference = xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha1Id,
						    NULL, (xmlChar*)uri, NULL);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
	id_attr = xmlHasProp(credential, (xmlChar *)"AssertionID");
	xmlAddID(NULL, doc, xmlGetProp(credential, (xmlChar *) "AssertionID"), id_attr);

	/* FIXME: X509 authentication needs X509 signature type */
	if (profile->server->certificate != NULL && profile->server->certificate[0] != 0) {
		key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
		xmlSecTmplKeyInfoAddX509Data(key_info);
	}

	/* Sign SOAP message */
	sign_tmpl = xmlSecFindNode(credential, xmlSecNodeSignature, xmlSecDSigNs);
	if (sign_tmpl == NULL)
		return LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND;

	dsigCtx = xmlSecDSigCtxCreate(NULL);
	dsigCtx->signKey = xmlSecCryptoAppKeyLoad(profile->server->private_key,
		xmlSecKeyDataFormatPem, NULL, NULL, NULL);
	if (dsigCtx->signKey == NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED;
	}
	if (profile->server->certificate != NULL && profile->server->certificate[0] != 0) {
		if (xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, profile->server->certificate,
					xmlSecKeyDataFormatPem) < 0) {
			xmlSecDSigCtxDestroy(dsigCtx);
			return LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED;
		}
	}

	if (xmlSecDSigCtxSign(dsigCtx, sign_tmpl) < 0) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return LASSO_DS_ERROR_SIGNATURE_FAILED;
	}
	xmlSecDSigCtxDestroy(dsigCtx);

	return 0;
}

static xmlSecKey*
lasso_wsf_profile_get_public_key_from_credential(LassoWsfProfile *profile, xmlNode *credential)
{
	xmlNode *authentication_statement, *subject, *subject_confirmation, *key_info;
	xmlSecKeyPtr public_key;
	xmlSecKeyInfoCtx *ctx;

	/* get AuthenticationStatement element */
	authentication_statement = credential->children;
	while (authentication_statement) {
		if (authentication_statement->type == XML_ELEMENT_NODE &&
				strcmp((char*)authentication_statement->name,
					"AuthenticationStatement") == 0)
			break;
		authentication_statement = authentication_statement->next;
	}
	if (authentication_statement == NULL) {
		return NULL;
	}

	/* get Subject element */
	subject = authentication_statement->children;
	while (subject) {
		if (subject->type == XML_ELEMENT_NODE &&
				strcmp((char*)subject->name, "Subject") == 0)
			break;
		subject = subject->next;
	}
	if (subject == NULL) {
		return NULL;
	}

	/* get SubjectConfirmation */
	subject_confirmation = subject->children;
	while (subject_confirmation) {
		if (subject_confirmation->type == XML_ELEMENT_NODE &&
		    strcmp((char*)subject_confirmation->name, "SubjectConfirmation") == 0)
			break;
		subject_confirmation = subject_confirmation->next;
	}
	if (subject_confirmation == NULL) {
		return NULL;
	}

	/* get KeyInfo */
	key_info = subject_confirmation->children;
	while (key_info) {
		if (key_info->type == XML_ELEMENT_NODE &&
				strcmp((char*)key_info->name, "KeyInfo") == 0)
			break;
		key_info = key_info->next;
	}
	if (!key_info)
		return NULL;

	ctx = xmlSecKeyInfoCtxCreate(NULL);
	xmlSecKeyInfoCtxInitialize(ctx, NULL);

	ctx->mode = xmlSecKeyInfoModeRead;
	ctx->keyReq.keyType = xmlSecKeyDataTypePublic;

	public_key = xmlSecKeyCreate();

	/* FIXME: get xml sec key from key_info instead of a rebuilt local node */
	/* xmlSecKeyInfoNodeRead(key_info, public_key, ctx); */

	{
		xmlDoc *doc;
		xmlChar *modulus_value, *exponent_value;
		xmlNode *rsa_key_value, *xmlnode, *modulus, *exponent;

		xmlnode = key_info->children;
		while (xmlnode) {
			if (strcmp((char*)xmlnode->name, "KeyValue") == 0) {
				break;
			}
			xmlnode = xmlnode->next;
		}
		rsa_key_value = xmlnode->children;
		while (rsa_key_value) {
			if (strcmp((char*)rsa_key_value->name, "RsaKeyValue") == 0) {
				break;
			}
			rsa_key_value = rsa_key_value->next;
		}
		xmlnode = rsa_key_value->children;
		while (xmlnode) {
			if (strcmp((char*)xmlnode->name, "Modulus") == 0) {
				modulus_value = xmlNodeGetContent(xmlnode);
			} else if (strcmp((char*)xmlnode->name, "Exponent") == 0) {
				exponent_value = xmlNodeGetContent(xmlnode);
			}
			xmlnode = xmlnode->next;
		}
		
		doc = xmlSecCreateTree((xmlChar*)"KeyInfo",
				(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");
		key_info = xmlDocGetRootElement(doc);

		xmlnode = xmlSecAddChild(key_info, (xmlChar*)"KeyValue",
				(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");
		xmlnode = xmlSecAddChild(xmlnode, (xmlChar*)"RSAKeyValue",
				(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");
		modulus = xmlSecAddChild(xmlnode, (xmlChar*)"Modulus",
				(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");
		xmlNodeSetContent(modulus, modulus_value);
		
		exponent = xmlSecAddChild(xmlnode, (xmlChar*)"Exponent",
				(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");
		xmlNodeSetContent(exponent, exponent_value);
	}
	
	xmlSecKeyInfoNodeRead(key_info, public_key, ctx);

	return public_key;
}

static gint
lasso_wsf_profile_verify_saml_authentication(LassoWsfProfile *profile, xmlDoc *doc)
{
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj;
	xmlNode *credential;
	xmlSecKey *public_key;
	int res;

	xpathCtx = xmlXPathNewContext(doc);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"wsse", (xmlChar*)LASSO_WSSE_HREF);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"saml", (xmlChar*)LASSO_SAML_ASSERTION_HREF);

	xpathObj = xmlXPathEvalExpression((xmlChar*)"//wsse:Security/saml:Assertion", xpathCtx);

	/* FIXME: Need to consider more every credentials. */
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeContext(xpathCtx);
		xmlXPathFreeObject(xpathObj);
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;
	}
	

	credential = xpathObj->nodesetval->nodeTab[0];

	res = lasso_wsf_profile_verify_credential_signature(profile, doc, credential);
	if (res < 0) {
		xmlXPathFreeContext(xpathCtx);
		xmlXPathFreeObject(xpathObj);
		return res;
	}
	
	public_key = lasso_wsf_profile_get_public_key_from_credential(profile, credential);
	xmlXPathFreeContext(xpathCtx);
	xmlXPathFreeObject(xpathObj);
	
	if (public_key == NULL) {
		return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
	}

	res = lasso_wsf_profile_verify_x509_authentication(profile, doc, public_key);
	xmlSecKeyDestroy(public_key);
	if (res != 0)
		return res;

	return 0;
}

static gint
lasso_wsf_profile_add_soap_signature(LassoWsfProfile *profile,
		xmlDoc *doc, xmlNode *envelope_node, LassoSignatureMethod sign_method)
{
	xmlNode *signature = NULL, *sign_tmpl, *reference, *key_info, *t;
	xmlNode *header = NULL, *provider = NULL, *correlation = NULL, *security = NULL;
	xmlNode *body = NULL;
	xmlSecDSigCtx *dsigCtx;
	xmlChar *id;
	char *uri;
	xmlAttr *id_attr;

	/* Get Correlation, Provider, Security, Body elements */
	t = envelope_node->children;
	while (t) {
		if (strcmp((char *) t->name, "Header") == 0) {
			header = t;
		} else if (strcmp((char *) t->name, "Body") == 0) {
			body = t;
		}
		t = t->next;
	}
	if (header == NULL)
		return LASSO_SOAP_ERROR_MISSING_HEADER;

	if (body == NULL)
		return LASSO_SOAP_ERROR_MISSING_BODY;

	t = header->children;
	while (t) {
		if (strcmp((char *) t->name, "Correlation") == 0) {
			correlation = t;
		} else if (strcmp((char *) t->name, "Provider") == 0) {
			provider = t;
		} else if (strcmp((char *) t->name, "Security") == 0) {
			security = t;
		}
		t = t->next;
	}
	if (correlation == NULL)
		return LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION;
	if (security == NULL)
		return LASSO_WSF_PROFILE_ERROR_MISSING_SECURITY;

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

	/* Correlation reference */
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

	/* Body reference */
	id = xmlGetProp(body, (xmlChar *) "id");
	uri = g_strdup_printf("#%s", id);
	reference = xmlSecTmplSignatureAddReference(signature, xmlSecTransformSha1Id,
						    NULL, (xmlChar *)uri, NULL);
	g_free(uri);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
	id_attr = xmlHasProp(body, (xmlChar *)"id");
	xmlAddID(NULL, doc, (xmlChar *)id, id_attr);
	xmlFree(id);

	/* Provider reference */
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
	sign_tmpl = signature;

	dsigCtx = xmlSecDSigCtxCreate(NULL);
	dsigCtx->signKey = xmlSecCryptoAppKeyLoad(profile->server->private_key,
		xmlSecKeyDataFormatPem, NULL, NULL, NULL);
	if (dsigCtx->signKey == NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED;
	}
	if (profile->server->certificate != NULL && profile->server->certificate[0] != 0) {
		if (xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, profile->server->certificate,
					xmlSecKeyDataFormatPem) < 0) {
			xmlSecDSigCtxDestroy(dsigCtx);
			return LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED;
		}
	}
	if (xmlSecDSigCtxSign(dsigCtx, sign_tmpl) < 0) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return LASSO_DS_ERROR_SIGNATURE_FAILED;
	}
	xmlSecDSigCtxDestroy(dsigCtx);

	return 0;
}

gint
lasso_wsf_profile_verify_x509_authentication(LassoWsfProfile *profile,
					     xmlDoc *doc, xmlSecKey *public_key)
{
	LassoProvider *lasso_provider = NULL;

	xmlNode *provider = NULL, *correlation = NULL, *body = NULL;
	xmlNode *x509data = NULL, *node;
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
	if (correlation == NULL) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		return LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION;
	}

	id_attr = xmlHasProp(correlation, (xmlChar *)"id");
	id = xmlGetProp(correlation, (xmlChar *) "id");
	xmlAddID(NULL, doc, id, id_attr);
	xmlFree(id);

	xmlXPathFreeObject(xpathObj);
	xpathObj = NULL;

	/* Body */
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		body = xpathObj->nodesetval->nodeTab[0];
	}
	if (body == NULL) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		return LASSO_SOAP_ERROR_MISSING_BODY;
	}

	id_attr = xmlHasProp(body, (xmlChar *)"id");
	id = xmlGetProp(body, (xmlChar *) "id");
	xmlAddID(NULL, doc, id, id_attr);
	xmlFree(id);

	xmlXPathFreeObject(xpathObj);
	xpathObj = NULL;

	/* Provider */
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

	xmlXPathFreeObject(xpathObj);
	xpathObj = NULL;

	/* Verify signature */
	node = NULL;
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"ds", (xmlChar*)LASSO_DS_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ds:Signature", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		node = xpathObj->nodesetval->nodeTab[0];
	}
	if (node == NULL) {
		xmlXPathFreeContext(xpathCtx);
		xmlXPathFreeObject(xpathObj);
		return LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
	}

	/* Case of X509 signature type */
	x509data = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeX509Data, xmlSecDSigNs);
	if (x509data != NULL && lasso_provider != NULL && lasso_provider->ca_cert_chain != NULL) {
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
				lasso_provider->ca_cert_chain);
		if (keys_mngr == NULL) {
			xmlXPathFreeObject(xpathObj);
			xmlXPathFreeContext(xpathCtx);
			return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
		}
	} else if (x509data != NULL) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
	}

	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);

	/* Case of simple public key signature type */
	if (keys_mngr == NULL) {
		if (lasso_provider != NULL) {
			dsigCtx->signKey = xmlSecKeyDuplicate(
					lasso_provider_get_public_key(lasso_provider));
		} else if (public_key) {
			dsigCtx->signKey = xmlSecKeyDuplicate(public_key);
		}
		if (dsigCtx->signKey == NULL) {
			xmlSecDSigCtxDestroy(dsigCtx);
			xmlXPathFreeObject(xpathObj);
			xmlXPathFreeContext(xpathCtx);
			return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
		}
	}

	if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
		xmlSecDSigCtxDestroy(dsigCtx);
		if (keys_mngr)
			xmlSecKeysMngrDestroy(keys_mngr);
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		return LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
	}

	xmlXPathFreeObject(xpathObj);
	xmlXPathFreeContext(xpathCtx);

	if (keys_mngr)
		xmlSecKeysMngrDestroy(keys_mngr);

	if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
		xmlSecDSigCtxDestroy(dsigCtx);
		return LASSO_DS_ERROR_INVALID_SIGNATURE;
	}

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

LassoDsKeyInfo*
lasso_wsf_profile_get_key_info_node(LassoWsfProfile *profile, const gchar *providerID)
{
	LassoDsKeyInfo *key_info = NULL;
	LassoDsRsaKeyValue *rsa_key_value = NULL;
	LassoDsKeyValue *key_value = NULL;
	LassoProvider *provider = NULL;
	xmlSecKeyInfoCtx *ctx = NULL;
	xmlSecKey *public_key = NULL;
	xmlDoc *doc = NULL;
	xmlNode *key_info_node = NULL;
	xmlNode *xmlnode = NULL;
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj = NULL;

	g_return_val_if_fail(providerID != NULL, NULL);

	provider = lasso_server_get_provider(profile->server, providerID);
	if (provider == NULL) {
		return NULL;
	}

	public_key = lasso_provider_get_public_key(provider);
	if (public_key == NULL) {
		return NULL;
	}

	ctx = xmlSecKeyInfoCtxCreate(NULL);
	xmlSecKeyInfoCtxInitialize(ctx, NULL);
	ctx->mode = xmlSecKeyInfoModeWrite;
	ctx->keyReq.keyType = xmlSecKeyDataTypePublic;

	doc = xmlSecCreateTree((xmlChar*)"KeyInfo",
			(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");
	key_info_node = xmlDocGetRootElement(doc);
	xmlSecAddChild(key_info_node, (xmlChar*)"KeyValue",
			(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");

	xmlSecKeyInfoNodeWrite(key_info_node, public_key, ctx);

	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"ds",
			(xmlChar*)"http://www.w3.org/2000/09/xmldsig#");

	rsa_key_value = lasso_ds_rsa_key_value_new();
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ds:Modulus", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		xmlnode = xpathObj->nodesetval->nodeTab[0];
		rsa_key_value->Modulus = (gchar *) xmlNodeGetContent(xmlnode);
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)"//ds:Exponent", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		xmlnode = xpathObj->nodesetval->nodeTab[0];
		rsa_key_value->Exponent = (gchar *) xmlNodeGetContent(xmlnode);
	}
	xmlXPathFreeObject(xpathObj);

	key_value = lasso_ds_key_value_new();
	key_value->RSAKeyValue = rsa_key_value;
	key_info = lasso_ds_key_info_new();
	key_info->KeyValue = key_value;

	xmlXPathFreeContext(xpathCtx);
	xmlFreeDoc(doc);

	return key_info;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_wsf_profile_is_principal_online():
 * @profile: a #LassoWsfProfile
 *
 * Check if the principal is set to be online.
 *
 **/
gboolean
lasso_wsf_profile_principal_is_online(LassoWsfProfile *profile)
{
	LassoSoapHeader *header;
	LassoSoapBindingProcessingContext *processing_context = NULL;
	GList *iter;

	g_return_val_if_fail(LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request), FALSE);

	header = profile->soap_envelope_request->Header;
	iter = header->Other;
	while (iter) {
		if (LASSO_IS_SOAP_BINDING_PROCESSING_CONTEXT(iter->data) == TRUE) {
			processing_context = iter->data;
			break;
		}
		iter = g_list_next(iter);
	}
	if (!processing_context)
		return FALSE;
	if (!processing_context->content)
		return FALSE;

	if (strcmp(processing_context->content,
		   LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_ONLINE) == 0)
		return TRUE;

	return FALSE;
}

/**
 * lasso_wsf_profile_set_principal_online():
 * @profile: a #LassoWsfProfile
 * @status : a char* representing status of principal.
 *
 * Set the status of the principal.
 *
 **/
void
lasso_wsf_profile_set_principal_status(LassoWsfProfile *profile, const char *status)
{
	LassoSoapHeader *header;
	LassoSoapBindingProcessingContext *processing_context = NULL;
	GList *iter;

	g_return_if_fail(LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request));

	header = profile->soap_envelope_request->Header;
	iter = header->Other;
	while (iter) {
		if (LASSO_IS_SOAP_BINDING_PROCESSING_CONTEXT(iter->data)) {
			processing_context = iter->data;
			break;
		}
		iter = g_list_next(iter);
	}
	if (!processing_context) {
		processing_context = LASSO_SOAP_BINDING_PROCESSING_CONTEXT(
			lasso_soap_binding_processing_context_new());
		header->Other = g_list_append(header->Other, processing_context);
	}
	if (processing_context->content)
		g_free(processing_context->content);
	processing_context->content = g_strdup(status);		
}

/**
 * lasso_wsf_profile_set_principal_online():
 * @profile: a #LassoWsfProfile
 *
 * Set the principal status as offline.
 *
 **/
void
lasso_wsf_profile_set_principal_online(LassoWsfProfile *profile)
{
	lasso_wsf_profile_set_principal_status(
		profile, LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_ONLINE);
}

/**
 * lasso_wsf_profile_set_principal_offline():
 * @profile: a #LassoWsfProfile
 *
 * Set the principal status as offline.
 *
 **/
void
lasso_wsf_profile_set_principal_offline(LassoWsfProfile *profile)
{
	lasso_wsf_profile_set_principal_status(
		profile, LASSO_SOAP_BINDING_PROCESS_CONTEXT_PRINCIPAL_OFFLINE);
}

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
	LassoWsseSecurity *security = NULL;
	int ret;
	GList *iter = NULL;
	xmlNode *security_xmlNode, *credential;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	xmlDoc *doc = NULL;
	xmlNode *envelope_node = NULL;
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj = NULL;
			

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request),
		LASSO_SOAP_ERROR_MISSING_ENVELOPE);

	envelope = profile->soap_envelope_request;

	/* FIXME: find a better way to add needed security element */
	if (lasso_wsf_profile_has_saml_authentication(profile) == TRUE ||
			lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		security = lasso_wsse_security_new();
		header = envelope->Header;
		header->Other = g_list_append(header->Other, security);
	}

	/* Apply wsf authentication */
	doc = xmlNewDoc((xmlChar*)"1.0");
	envelope_node = lasso_node_get_xmlNode(LASSO_NODE(envelope), FALSE);
	xmlDocSetRootElement(doc, envelope_node);

	if (lasso_wsf_profile_has_saml_authentication(profile) == TRUE) {
		if (profile->private_data->credentials) {
			xpathCtx = xmlXPathNewContext(doc);
			
			xmlXPathRegisterNs(xpathCtx, (xmlChar*)"wsse", (xmlChar*)LASSO_WSSE_HREF);
			xpathObj = xmlXPathEvalExpression((xmlChar*)"//wsse:Security", xpathCtx);

			if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
				security_xmlNode = xpathObj->nodesetval->nodeTab[0];
				iter = profile->private_data->credentials;
				
				/* FIXME: not sure it's the proper way to avoid ns error */
				xmlNewNs(envelope_node,
						(xmlChar*)LASSO_SAML_ASSERTION_HREF,
						(xmlChar*)LASSO_SAML_ASSERTION_PREFIX);
				xmlNewNs(envelope_node,
						(xmlChar*)LASSO_DS_HREF,
						(xmlChar*)LASSO_DS_PREFIX);
				
				while (iter) {
					credential = (xmlNode *) iter->data;
					credential = xmlAddChild(security_xmlNode, credential);
					iter = iter->next;
				}
				/* xml doc has xml node credentials, so remove profile
				   credential list */
				g_list_free(profile->private_data->credentials);
			}

			xmlXPathFreeContext(xpathCtx);
			xmlXPathFreeObject(xpathObj);
			xpathCtx = NULL;
			xpathObj = NULL;
		}

		/* FIXME: do we need to sign if SAML authentication or X509 authentication ? */
		ret = lasso_wsf_profile_add_soap_signature(profile, doc, envelope_node,
							   LASSO_SIGNATURE_METHOD_RSA_SHA1);
		if (ret != 0) {
			xmlFreeDoc(doc);
			return ret;
		}
	}

	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		ret = lasso_wsf_profile_add_soap_signature(profile, doc, envelope_node,
							   LASSO_SIGNATURE_METHOD_RSA_SHA1);
		if (ret != 0) {
			xmlFreeDoc(doc);
			return ret;
		}
	}

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

static int
lasso_wsf_profile_ensure_soap_credentials_signature(LassoWsfProfile *profile,
		xmlDoc *doc, xmlNode *soap_envelope)
{
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj;
	int i;

	xpathCtx = xmlXPathNewContext(doc);

	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"wsse", (xmlChar*)LASSO_WSSE_HREF);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"saml", (xmlChar*)LASSO_SAML_ASSERTION_HREF);

	/* FIXME: should find credential from //wsse:Security/saml:Assertion instead.*/
	xpathObj = xmlXPathEvalExpression((xmlChar*)"//saml:Assertion", xpathCtx);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
		for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
			lasso_wsf_profile_add_credential_signature(profile, doc,
				xpathObj->nodesetval->nodeTab[i], LASSO_SIGNATURE_METHOD_RSA_SHA1);
		}
	}

	xmlXPathFreeContext(xpathCtx);
	xmlXPathFreeObject(xpathObj);

	return 0;
}

int
lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *profile)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoWsseSecurity *security;

	xmlNode *soap_envelope;

	xmlDoc *doc;

	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* FIXME: find a better way to add needed security element */
	envelope = profile->soap_envelope_response;
	if (lasso_wsf_profile_has_saml_authentication(profile) == TRUE ||
			lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		security = lasso_wsse_security_new();
		header = envelope->Header;
		header->Other = g_list_append(header->Other, security);
	}

	/* Apply wsf authentication */
	doc = xmlNewDoc((xmlChar*)"1.0");
	soap_envelope = lasso_node_get_xmlNode(LASSO_NODE(envelope), TRUE);
	xmlDocSetRootElement(doc, soap_envelope);

	/* SAML authentication, if credentials in response, verify they are signed */
	lasso_wsf_profile_ensure_soap_credentials_signature(profile, doc, soap_envelope);

	/* X509 authentication */
	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		int res = lasso_wsf_profile_add_soap_signature(profile, doc, soap_envelope,
							       LASSO_SIGNATURE_METHOD_RSA_SHA1);
		if (res != 0) {
			xmlFreeDoc(doc);
			return res;
		}
	}

	/* Dump soap response */
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, soap_envelope, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);
	xmlFreeDoc(doc);

	return 0;
}

gint
lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile, const gchar *message,
					   const gchar *service_type, const gchar *security_mech_id)
{
	LassoDiscoServiceInstance *si = NULL;
	LassoSoapBindingCorrelation *correlation = NULL;
	LassoSoapEnvelope *envelope = NULL;
	LassoSoapFault *fault = NULL;
	gchar *messageId;
	int res = 0;
	xmlDoc *doc;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	si = lasso_server_get_service(profile->server, (char *) service_type);

	if (security_mech_id == NULL) {
		if (si) {
			profile->private_data->description = LASSO_DISCO_DESCRIPTION(
				si->Description->data);
		} else {
			profile->private_data->description = NULL;
		}
	} else {
		if (si == NULL) {
			return LASSO_PROFILE_ERROR_MISSING_SERVICE_INSTANCE;
		} else {
			lasso_wsf_profile_get_description_auto(si, security_mech_id);	
		}
	}

	doc = lasso_xml_parse_memory(message, strlen(message));

	/* Verify authentication mecanisms */
	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		res = lasso_wsf_profile_verify_x509_authentication(profile, doc, NULL);
	} else if (lasso_wsf_profile_has_saml_authentication(profile) == TRUE) {
		res = lasso_wsf_profile_verify_saml_authentication(profile, doc);
	}

	/* FIXME: Return a soap fault if authentication verification failed ? */
	if (res > 0) {
		fault = lasso_soap_fault_new();
		fault->faultstring = g_strdup("Invalid signature");
	} else if (res < 0) {
		xmlFreeDoc(doc);
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

	/* Get soap request and his message id */
	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	profile->soap_envelope_request = envelope;
	profile->request = LASSO_NODE(envelope->Body->any->data);

	/* Get the correlation header */
        {
		GList *iter = envelope->Header->Other;
		while (iter && ! LASSO_IS_SOAP_BINDING_CORRELATION(iter->data)) {
			iter = iter->next;
		}
		if (iter) {
			correlation = LASSO_SOAP_BINDING_CORRELATION(iter->data);
		} 
	}
	if (correlation == NULL || correlation->messageID == NULL) {
		return LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION;
	}
	messageId = correlation->messageID;

	/* Set soap response */
	envelope = lasso_wsf_profile_build_soap_envelope(messageId,
		LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_WSF_PROFILE(profile)->soap_envelope_response = envelope;

	/* If fault built at this level (X509 authentication error ?),
	   then save it in soap response */
	if (fault) {
		envelope->Body->any = g_list_append(envelope->Body->any, fault);
		/* FIXME: Need to store it in private data's profile ? */
		profile->private_data->fault = fault;
	}

	xmlFreeDoc(doc);

	return res;
}

gint
lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope;
	xmlNode *credential;
	int res = 0;

	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj;

	xmlDoc *doc;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	doc = lasso_xml_parse_memory(message, strlen(message));

	if (lasso_wsf_profile_has_x509_authentication(profile) == TRUE) {
		xmlNode *xmlnode;
		int res;

		res = lasso_wsf_profile_verify_x509_authentication(profile, doc, NULL);
		if (res != 0) {
			xmlFreeDoc(doc);
			return res;
		}

		/* FIXME: Remove Signature element if exists, it seg fault when a call to
		   lasso_node_new_from_xmlNode() */
		xmlnode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature,
					 xmlSecDSigNs);
		if (xmlnode) {
			xmlUnlinkNode(xmlnode);
			xmlFreeNode(xmlnode);
		}
	}

	if (res != 0) {
		xmlFreeDoc(doc);
		return res;
	}

	/* If credentials are found, save and remove them from message */
	{
		int i;

		xpathCtx = xmlXPathNewContext(doc);
		xmlXPathRegisterNs(xpathCtx, (xmlChar*)"saml", (xmlChar*)LASSO_SAML_ASSERTION_HREF);
		xpathObj = xmlXPathEvalExpression((xmlChar*)"//saml:Assertion", xpathCtx);
		if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr) {
			for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
				credential = xpathObj->nodesetval->nodeTab[i];
				xmlUnlinkNode(credential);
				lasso_wsf_profile_add_credential(profile, credential);
			}
		}
		xmlXPathFreeContext(xpathCtx);
		xmlXPathFreeObject(xpathObj);
	}
	
	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	xmlFreeDoc(doc);

	profile->soap_envelope_response = envelope;

	if (envelope == NULL) {
		return critical_error(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);
	}

	/* Soap Fault message */
	if (LASSO_IS_SOAP_FAULT(envelope->Body->any->data) == FALSE)
		profile->response = LASSO_NODE(envelope->Body->any->data);

	return 0;
}

LassoSoapBindingProvider *lasso_wsf_profile_set_provider_soap_request(LassoWsfProfile *profile,
	const char *providerId)
{
	LassoSoapBindingProvider *provider;
	LassoSoapHeader *header;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), NULL);
	g_return_val_if_fail(providerId != NULL, NULL);
	g_return_val_if_fail(LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request), NULL);

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
}

static void
class_init(LassoWsfProfileClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "WsfProfile");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

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
