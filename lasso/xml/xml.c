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
 * SECTION:node
 * @short_description: Base class for all Lasso objects
 *
 * #LassoNode is the base class for Lasso objects; just a step over GObject as
 * defined in glib.
 *
 */

#include "private.h"
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <xmlsec/base64.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmlenc.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/openssl/x509.h>

#include "xml.h"
#include "xml_enc.h"
#include "saml_name_identifier.h"
#include "../utils.h"
#include "../registry.h"
#include "../debug.h"
#include "soap-1.1/soap_envelope.h"
#include "soap-1.1/soap_body.h"
#include "misc_text_node.h"
#include "../lasso_config.h"
#ifdef LASSO_WSF_ENABLED
#include "idwsf_strings.h"
#include "id-wsf-2.0/idwsf2_strings.h"
#endif

/* Needed for ECP */
#include "saml-2.0/samlp2_idp_list.h"
#include "paos_request.h"
#include "ecp/ecp_request.h"
#include "ecp/ecp_response.h"
#include "ecp/ecp_relaystate.h"

#include "../key.h"

static void lasso_node_build_xmlNode_from_snippets(LassoNode *node, LassoNodeClass *class, xmlNode *xmlnode,
		struct XmlSnippet *snippets, gboolean lasso_dump);
static struct XmlSnippet* find_xml_snippet_by_name(LassoNode *node, char *name, LassoNodeClass **class_p);
static gboolean set_value_at_path(LassoNode *node, char *path, char *query_value);
static char* get_value_by_path(LassoNode *node, char *path, struct XmlSnippet *xml_snippet);
static gboolean find_path(LassoNode *node, char *path, LassoNode **value_node,
		LassoNodeClass **class_p, struct XmlSnippet **snippet);

static void lasso_node_add_signature_template(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippet_signature);
static void lasso_node_traversal(LassoNode *node, void (*do_to_node)(LassoNode *node, SnippetType type), SnippetType type);

static LassoNode* lasso_node_new_from_xmlNode_with_type(xmlNode *xmlnode, char *typename);
static void lasso_node_remove_original_xmlnode(LassoNode *node, SnippetType type);

GHashTable *dst_services_by_href = NULL; /* ID-WSF 1 extra DST services, indexed on href */
GHashTable *dst_services_by_prefix = NULL; /* ID-WSF 1 extra DST services, indexed on prefix */

GHashTable *idwsf2_dst_services_by_href = NULL; /* ID-WSF 2 DST services, indexed on href */
GHashTable *idwsf2_dst_services_by_prefix = NULL; /* ID-WSF 2 DST services, indexed on prefix */

/*****************************************************************************/
/* global methods                                                            */
/*****************************************************************************/

/**
 * lasso_register_dst_service:
 * @prefix: prefix of DST service
 * @href: href of DST service
 *
 * Registers prefix and href of a custom data service template service.
 **/
void
lasso_register_dst_service(const gchar *prefix, const gchar *href)
{
	if (dst_services_by_href == NULL) {
		dst_services_by_href = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, g_free);
		dst_services_by_prefix = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, g_free);
	}
	g_hash_table_insert(dst_services_by_prefix, g_strdup(prefix), g_strdup(href));
	g_hash_table_insert(dst_services_by_href, g_strdup(href), g_strdup(prefix));
}

void
lasso_register_idwsf2_dst_service(const gchar *prefix, const gchar *href)
{
	if (idwsf2_dst_services_by_href == NULL) {
		idwsf2_dst_services_by_href = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, g_free);
		idwsf2_dst_services_by_prefix = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, g_free);
	}
	g_hash_table_insert(idwsf2_dst_services_by_prefix, g_strdup(prefix), g_strdup(href));
	g_hash_table_insert(idwsf2_dst_services_by_href, g_strdup(href), g_strdup(prefix));
}

gchar*
lasso_get_prefix_for_dst_service_href(const gchar *href)
{
	if (dst_services_by_href == NULL)
		return NULL;

	return g_strdup(g_hash_table_lookup(dst_services_by_href, href));
}

gchar*
lasso_get_prefix_for_idwsf2_dst_service_href(const gchar *href)
{
	if (idwsf2_dst_services_by_href == NULL)
		return NULL;

	return g_strdup(g_hash_table_lookup(idwsf2_dst_services_by_href, href));
}


/*****************************************************************************/
/* virtual public methods                                                    */
/*****************************************************************************/

static char*
_lasso_node_export_to_xml(LassoNode *node, gboolean format, gboolean dump, int level)
{
	xmlNode *xmlnode;
	char *ret;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

	xmlnode = lasso_node_get_xmlNode(node, dump);
	if (xmlnode == NULL) {
		return NULL;
	}
	ret = lasso_xmlnode_to_string(xmlnode, format, level);
	xmlFreeNode(xmlnode);

	return ret;
}

/**
 * lasso_node_dump:
 * @node: a #LassoNode
 *
 * Dumps @node.  All datas in object are dumped in an XML format.
 *
 * Return value:(transfer full): a full XML dump of @node.  The string must be freed by the
 *     caller.
 **/
char*
lasso_node_dump(LassoNode *node)
{
	return _lasso_node_export_to_xml(node, FALSE, TRUE, 0);
}

/**
 * lasso_node_debug:
 * @node: a #LassoNode
 * @level:(default 10): the indentation depth, i.e. the depth of the last nodes to be indented.
 *
 * Create a debug dump for @node, it is pretty printed so any contained signature will be
 * uncheckable.
 *
 * Return value:(transfer full): a full indented and so human readable dump of @node. The string must be freed by
 * the caller.
 */
char*
lasso_node_debug(LassoNode *node, int level)
{
	return _lasso_node_export_to_xml(node, TRUE, TRUE, level);
}

/**
 * lasso_node_destroy:
 * @node: a #LassoNode
 *
 * Destroys the #LassoNode.
 **/
void
lasso_node_destroy(LassoNode *node)
{
	if (node == NULL) {
		return;
	}
	if (LASSO_IS_NODE(node)) {
		LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
		class->destroy(node);
	}
}

/**
 * lasso_node_export_to_base64:
 * @node: a #LassoNode
 *
 * Exports @node to a base64-encoded message.
 *
 * Return value: a base64-encoded export of @node.  The string must be freed by
 *      the caller.
 **/
char*
lasso_node_export_to_base64(LassoNode *node)
{
	char *str;
	char *ret;

	g_return_val_if_fail(LASSO_IS_NODE(node), NULL);

	str = lasso_node_export_to_xml(node);
	if (str == NULL)
		return NULL;
	ret = (char*)xmlSecBase64Encode(BAD_CAST str, strlen(str), 0);
	lasso_release_string(str);
	return ret;
}

/**
 * lasso_node_export_to_ecp_soap_response:
 * @node: a #LassoNode
 *
 * Exports @node to a ECP SOAP message.
 *
 * Return value: a ECP SOAP export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_ecp_soap_response(LassoNode *node, const char *assertionConsumerURL)
{
	char *ret = NULL;
	LassoNode *ecp_response = NULL;
	GList *headers = NULL;

	lasso_return_null_if_fail(LASSO_IS_NODE(node));
	lasso_return_null_if_fail(assertionConsumerURL);

	/* Build the soap header elements */
	ecp_response = lasso_ecp_response_new(assertionConsumerURL);
	goto_cleanup_if_fail(ecp_response);
	lasso_list_add_new_gobject(headers, ecp_response);

	/* Create soap envelope and serialize into an xml document */
	ret = lasso_node_export_to_soap_with_headers(node, headers);

 cleanup:
	lasso_release_list_of_gobjects(headers);
	return ret;
}

/**
 * lasso_node_export_to_paos_request:
 * @node: a #LassoNode
 *
 * Exports @node to a PAOS message.
 *
 * Deprecated, use lasso_node_export_to_paos_request_full() instead
 *
 * Return value: a PAOS export of @node.  The string must be freed by the
 *      caller.
 **/
char *
lasso_node_export_to_paos_request(LassoNode *node, const char *issuer,
		const char *responseConsumerURL, const char *relay_state)
{
	return lasso_node_export_to_paos_request_full(node, issuer, responseConsumerURL,
												  NULL, relay_state, TRUE, NULL, NULL);
}

/**
 * lasso_node_export_to_paos_request_full:
 * @node:
 * @issuer:
 * @responseConsumerURL:
 * @message_id: (allow-none):
 * @relay_state: (allow-none):
 * @is_passive:
 * @provider_name: (allow-none):
 * @idp_list: (allow-none):
 *
 * Creates a new SOAP message. The SOAP headers include a PaosRequst,
 * a EcpRequest and optionally a EcpRelayState. The SOAP body contains
 * the @node parameters.
 *
 * Returns: string containing a PAOS request. The string must be freed
 * by the caller.
 **/
char *
lasso_node_export_to_paos_request_full(LassoNode *node, const char *issuer,
									   const char *responseConsumerURL, const char *message_id,
									   const char *relay_state, gboolean is_passive, gchar *provider_name,
									   LassoSamlp2IDPList *idp_list)
{
	char *ret = NULL;
	LassoNode *paos_request = NULL;
	LassoNode *ecp_request = NULL;
	LassoNode *ecp_relaystate = NULL;
	GList *headers = NULL;

	lasso_return_null_if_fail(LASSO_IS_NODE(node));
	lasso_return_null_if_fail(issuer);
	lasso_return_null_if_fail(responseConsumerURL);

	/* Build the soap header elements */
	paos_request = lasso_paos_request_new(responseConsumerURL, message_id);
	goto_cleanup_if_fail(paos_request);
	lasso_list_add_new_gobject(headers, paos_request);

	ecp_request = lasso_ecp_request_new(issuer, is_passive, provider_name, idp_list);
	goto_cleanup_if_fail(ecp_request);
	lasso_list_add_new_gobject(headers, ecp_request);

	if (relay_state) {
		ecp_relaystate = lasso_ecp_relay_state_new(relay_state);
		goto_cleanup_if_fail(ecp_relaystate);
		lasso_list_add_new_gobject(headers, ecp_relaystate);
	}

	/* Create soap envelope and serialize into an xml document */
	ret = lasso_node_export_to_soap_with_headers(node, headers);

 cleanup:
	lasso_release_list_of_gobjects(headers);
	return ret;
}

/**
 * lasso_node_export_to_query:
 * @node: a #LassoNode
 * @sign_method:(default 1): the Signature transform method
 * @private_key_file:(allow-none): the path to the private key (may be NULL)
 *
 * Exports @node to a HTTP query string.  If @private_key_file is NULL,
 * query won't be signed.
 *
 * Return value: a HTTP query export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_query(LassoNode *node, LassoSignatureMethod sign_method,
		const char *private_key_file)
{
	return lasso_node_export_to_query_with_password(node, sign_method, private_key_file, NULL);
}

/**
 * lasso_node_export_to_query_with_password:
 * @node: a #LassoNode
 * @sign_method:(default 1): the Signature transform method
 * @private_key_file:(allow-none): the path to the private key (may be NULL)
 * @private_key_file_password:(allow-none): the password needed to decrypt the private key
 *
 * Exports @node to a HTTP query string.  If @private_key_file is NULL,
 * query won't be signed.
 *
 * Return value: a HTTP query export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_query_with_password(LassoNode *node,
		LassoSignatureMethod sign_method, const char *private_key_file,
		const char *private_key_file_password)
{
	char *unsigned_query, *query = NULL;
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;

	g_return_val_if_fail(LASSO_IS_NODE(node), NULL);

	context.signature_method = sign_method;
	context.signature_key = lasso_xmlsec_load_private_key(private_key_file,
			private_key_file_password, sign_method, NULL);

	if (! context.signature_key) {
		return NULL;
	}

	unsigned_query = lasso_node_build_query(node);
	if (unsigned_query){
		query = lasso_query_sign(unsigned_query, context);
		if (query) {
			lasso_release(unsigned_query);
			unsigned_query = query;
		}
	}
	lasso_release_sec_key(context.signature_key);
	return unsigned_query;
}

/**
 * lasso_node_export_to_xml:
 * @node: a #LassoNode
 *
 * Exports @node to an xml message.
 *
 * Return value: an xml export of @node.  The string must be freed by the
 *      caller.
 **/
gchar*
lasso_node_export_to_xml(LassoNode *node)
{
	return _lasso_node_export_to_xml(node, FALSE, FALSE, 0);
}

/**
 * lasso_node_export_to_soap:
 * @node: a #LassoNode
 *
 * Exports @node to a SOAP message.
 *
 * Return value: a SOAP export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_soap(LassoNode *node)
{
	LassoSoapEnvelope *envelope;
	LassoSoapBody *body;
	char *ret;

	g_return_val_if_fail(LASSO_IS_NODE(node), NULL);

	body = lasso_soap_body_new();
	envelope = lasso_soap_envelope_new(body);
	lasso_list_add_gobject(body->any, node);
	ret = lasso_node_export_to_xml((LassoNode*)envelope);
	lasso_release_gobject(envelope);
	lasso_release_gobject(body);
	return ret;
}

/**
 * lasso_node_export_to_soap_with_headers:
 * @node: a #LassoNode, becomes the SOAP body
 * @headers: (allow-none): #GList of #LassNode
 *
 * Exports @node to a SOAP message. The @node becomes the SOAP body.
 * each header in the #headers list is added to the SOAP header if non-NULL.
 * @headers is permitted to be an empty list (e.g. NULL).
 *
 * <example>
 * <title>Create SOAP envelope with variable number of header nodes</title>
 *
 * <para>You need to form a SOAP message with authn_request as the body and
 * paos_request, ecp_request and ecp_relaystate as SOAP header elements.
 * It is possible one or more of these may be NULL and should be skipped.</para>
 * <programlisting>
 * char *text = NULL;
 * LassoNode *paos_request = NULL;
 * LassoNode *ecp_request = NULL;
 * LassoNode *ecp_relaystate = NULL;
 * GList *headers = NULL;
 *
 * paos_request = lasso_paos_request_new(responseConsumerURL, message_id);
 * ecp_request = lasso_ecp_request_new(issuer, is_passive, provider_name, idp_list);
 *
 * lasso_list_add_new_gobject(headers, paos_request);
 * lasso_list_add_new_gobject(headers, ecp_request);
 * lasso_list_add_new_gobject(headers, ecp_relaystate);
 *
 * text = lasso_node_export_to_soap_with_headers(node, headers);
 *
 * lasso_release_list_of_gobjects(headers);
 * </programlisting>
 * </example>
 *
 * Return value: a SOAP export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_soap_with_headers(LassoNode *node, GList *headers)
{
	GList *i;
	LassoSoapEnvelope *envelope = NULL;
	LassoNode *header = NULL;
	char *ret = NULL;

	g_return_val_if_fail(LASSO_IS_NODE(node), NULL);

	envelope = lasso_soap_envelope_new_full();
	lasso_list_add_gobject(envelope->Body->any, node);

	lasso_foreach(i, headers) {
		header = i->data;
		if (!header) continue;

		goto_cleanup_if_fail(LASSO_IS_NODE(header));
		lasso_list_add_gobject(envelope->Header->Other, header); /* adds ref */
	}

	ret = lasso_node_export_to_xml((LassoNode*)envelope);

 cleanup:
	lasso_release_gobject(envelope);
	return ret;
}

/**
 * lasso_node_encrypt:
 * @lasso_node: a #LassoNode to encrypt
 * @encryption_public_key : RSA public key the node will be encrypted with
 *
 * Generate a DES key and encrypt it with the RSA key.
 * Then encrypt @lasso_node with the DES key.
 *
 * Return value: an xmlNode which is the @node in an encrypted fashion.
 * It must be freed by the caller.
 **/
LassoSaml2EncryptedElement*
lasso_node_encrypt(LassoNode *lasso_node, xmlSecKey *encryption_public_key,
		LassoEncryptionSymKeyType encryption_sym_key_type, const char *recipient)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr orig_node = NULL;
	LassoSaml2EncryptedElement *encrypted_element = NULL, *ret = NULL;
	xmlSecKeysMngrPtr key_manager = NULL;
	xmlNodePtr key_info_node = NULL;
	xmlNodePtr encrypted_key_node = NULL;
	xmlNodePtr encrypted_data = NULL;
	xmlNodePtr key_info_node2 = NULL;
	xmlSecEncCtxPtr enc_ctx = NULL;
	xmlSecTransformId xmlsec_encryption_sym_key_type;
	xmlSecKey *duplicate = NULL;

	if (encryption_public_key == NULL || !xmlSecKeyIsValid(encryption_public_key)) {
		message(G_LOG_LEVEL_WARNING, "Invalid encryption key");
		goto cleanup;
	}

	/* Create a document to contain the node to encrypt */
	doc = xmlNewDoc((xmlChar*)"1.0");
	orig_node = lasso_node_get_xmlNode(lasso_node, FALSE);
	xmlDocSetRootElement(doc, orig_node);

	/* Get the symetric key type */
	switch (encryption_sym_key_type) {
		case LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_256:
			xmlsec_encryption_sym_key_type = xmlSecTransformAes256CbcId;
			break;
		case LASSO_ENCRYPTION_SYM_KEY_TYPE_3DES:
			xmlsec_encryption_sym_key_type = xmlSecTransformDes3CbcId;
			break;
		case LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_128:
		default:
			xmlsec_encryption_sym_key_type = xmlSecTransformAes128CbcId;
			break;
	}

	/* Create encryption template for a specific symetric key type */
	/* saml-core 2.2.4 line 498:
	 * The Type attribute SHOULD be present and, if present, MUST contain a value of
	 * http://www.w3.org/2001/04/xmlenc#Element. */
	encrypted_data = xmlSecTmplEncDataCreate(doc,
			xmlsec_encryption_sym_key_type,	NULL, xmlSecTypeEncElement, NULL, NULL);

	if (encrypted_data == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to create encryption template");
		goto cleanup;
	}

	if (xmlSecTmplEncDataEnsureCipherValue(encrypted_data) == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to add CipherValue node");
		goto cleanup;
	}

	/* create and initialize keys manager, we use a simple list based
	 * keys manager, implement your own xmlSecKeysStore klass if you need
	 * something more sophisticated
	 */
	key_manager = xmlSecKeysMngrCreate();
	if (key_manager == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to create keys manager");
		goto cleanup;
	}

	if (xmlSecCryptoAppDefaultKeysMngrInit(key_manager) < 0) {
		message(G_LOG_LEVEL_WARNING, "Failed to initialize keys manager");
		goto cleanup;
	}

	/* add key to keys manager, from now on keys manager is responsible
	 * for destroying key
	 */
	duplicate = xmlSecKeyDuplicate(encryption_public_key);
	if (xmlSecCryptoAppDefaultKeysMngrAdoptKey(key_manager, duplicate) < 0) {
		lasso_release_sec_key(duplicate);
		goto cleanup;
	}

	/* add <dsig:KeyInfo/> */
	key_info_node = xmlSecTmplEncDataEnsureKeyInfo(encrypted_data, NULL);
	if (key_info_node == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to add key info");
		goto cleanup;
	}

	/* add <enc:EncryptedKey/> to store the encrypted session key */
	encrypted_key_node = xmlSecTmplKeyInfoAddEncryptedKey(key_info_node,
			xmlSecTransformRsaPkcs1Id, NULL, NULL, (xmlChar*)recipient);
	if (encrypted_key_node == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to add encrypted key");
		goto cleanup;
	}

	/* we want to put encrypted key in the <enc:CipherValue/> node */
	if (xmlSecTmplEncDataEnsureCipherValue(encrypted_key_node) == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to add CipherValue node");
		goto cleanup;
	}

	/* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to <enc:EncryptedKey/> */
	key_info_node2 = xmlSecTmplEncDataEnsureKeyInfo(encrypted_key_node, NULL);
	if (key_info_node2 == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to add key info");
		goto cleanup;
	}
	/* check id of the key */
	if (xmlSecKeyGetData(encryption_public_key, xmlSecOpenSSLKeyDataRsaId) != 0) {
		xmlNode *key_value = xmlSecTmplKeyInfoAddKeyValue(key_info_node2);
		if (key_value == NULL) {
			message(G_LOG_LEVEL_WARNING, "Failed to add key value");
			goto cleanup;
		}
	} else { /* it must be a certificate */
		xmlNodePtr x509_data;
		x509_data = xmlSecTmplKeyInfoAddX509Data(key_info_node2);
		if (x509_data == NULL) {
			message(G_LOG_LEVEL_WARNING, "Failed to add X509 data");
			goto cleanup;
		}
	}




	/* create encryption context */
	enc_ctx = (xmlSecEncCtxPtr)xmlSecEncCtxCreate(key_manager);
	if (enc_ctx == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to create encryption context");
		goto cleanup;
	}

	/* generate a symetric key */
	switch (encryption_sym_key_type) {
		case LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_256:
			enc_ctx->encKey = xmlSecKeyGenerate(xmlSecKeyDataAesId, 256,
					xmlSecKeyDataTypeSession);
			break;
		case LASSO_ENCRYPTION_SYM_KEY_TYPE_3DES:
			enc_ctx->encKey = xmlSecKeyGenerate(xmlSecKeyDataDesId, 192,
					xmlSecKeyDataTypeSession);
			break;
		case LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_128:
		default:
			enc_ctx->encKey = xmlSecKeyGenerate(xmlSecKeyDataAesId, 128,
					xmlSecKeyDataTypeSession);
			break;
	}

	if (enc_ctx->encKey == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to generate session des key");
		goto cleanup;
	}


	/* encrypt the data */
	if (xmlSecEncCtxXmlEncrypt(enc_ctx, encrypted_data, orig_node) < 0) {
		message(G_LOG_LEVEL_WARNING, "Encryption failed");
		goto cleanup;
	}


	/* Create a new EncryptedElement */
	encrypted_element = LASSO_SAML2_ENCRYPTED_ELEMENT(lasso_saml2_encrypted_element_new());
	lasso_assign_gobject(encrypted_element->original_data, lasso_node);
	lasso_assign_xml_node(encrypted_element->EncryptedData, xmlDocGetRootElement(doc));
	lasso_transfer_gobject(ret, encrypted_element);

cleanup:
	lasso_release_key_manager(key_manager);
	lasso_release_gobject(encrypted_element);
	lasso_release_encrypt_context(enc_ctx);
	lasso_release_doc(doc);

	return ret;
}


/**
 * lasso_node_init_from_query:
 * @node: a #LassoNode (or derived class)
 * @query: the query string
 *
 * Initialiazes @node fields with data from @query string.
 *
 * Return value: %TRUE if success
 **/
gboolean
lasso_node_init_from_query(LassoNode *node, const char *query)
{
	LassoNodeClass *class;
	char **query_fields;
	int i;
	gboolean rc;

	g_return_val_if_fail(LASSO_IS_NODE(node), FALSE);
	class = LASSO_NODE_GET_CLASS(node);

	query_fields = urlencoded_to_strings(query);
	rc = class->init_from_query(node, query_fields);
	for (i = 0; query_fields[i]; i++) {
		xmlFree(query_fields[i]);
		query_fields[i] = NULL;
	}
	lasso_release(query_fields);
	return rc;
}


/**
 * lasso_node_init_from_xml:
 * @node: a #LassoNode (or derived class)
 * @xmlnode: the libxml2 node
 *
 * Initialiazes @node fields with data from @xmlnode XML node.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_node_init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoNodeClass *class;

	g_return_val_if_fail(LASSO_IS_NODE(node), LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED);
	class = LASSO_NODE_GET_CLASS(node);

	return class->init_from_xml(node, xmlnode);
}

/**
 * lasso_node_build_query:
 * @node: a #LassoNode
 *
 * Build an HTTP query from the given LassoNode, this is a pure virtual
 * function, you must overload it in subclass.
 *
 * Return value: a newly allocated string containing the query if it succeed,
 * or NULL otherwise.
 */
char*
lasso_node_build_query(LassoNode *node)
{
	LassoNodeClass *class;
	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

	class = LASSO_NODE_GET_CLASS(node);
	return class->build_query(node);
}

static LassoNodeClassData*
lasso_legacy_get_signature_node_data(LassoNode *node, LassoNodeClass **out_klass)
{
	LassoNodeClass *klass = NULL;
	LassoNodeClassData *node_data = NULL;

	klass = LASSO_NODE_GET_CLASS(node);
	/* find a klass defining a signature */
	while (klass && LASSO_IS_NODE_CLASS(klass)) {
		if (klass->node_data && klass->node_data->sign_type_offset) {
			if (out_klass) {
				*out_klass = klass;
			}
			node_data = klass->node_data;
			break;
		}
		klass = g_type_class_peek_parent(klass);
	}

	return node_data;
}

static gboolean
lasso_legacy_extract_and_copy_signature_parameters(LassoNode *node, LassoNodeClassData *node_data)
{
	LassoSignatureMethod signature_method = LASSO_SIGNATURE_METHOD_NONE;
	char *private_key_file = NULL;
	char *certificate_file = NULL;

	if (! node_data) {
		return FALSE;
	}
	signature_method = G_STRUCT_MEMBER(LassoSignatureMethod, node,
			node_data->sign_method_offset);
	private_key_file = G_STRUCT_MEMBER(char *, node, node_data->private_key_file_offset);
	certificate_file = G_STRUCT_MEMBER(char *, node, node_data->certificate_file_offset);
	if (! lasso_validate_signature_method(signature_method)) {
		return FALSE;
	}
	if (lasso_node_set_signature(node,
			lasso_make_signature_context_from_path_or_string(private_key_file, NULL,
				signature_method, certificate_file)) != 0) {
		return FALSE;
	}
	return TRUE;
}

/**
 * lasso_node_get_xmlNode:
 * @node: a #LassoNode
 * @lasso_dump: whether to include lasso-specific nodes
 *
 * Builds an XML representation of @node.
 *
 * Return value: a new xmlNode.  It must be freed by the caller.
 **/
xmlNode*
lasso_node_get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode = NULL;
	LassoSignatureContext context;
	LassoNodeClassData *node_data;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
	xmlnode = LASSO_NODE_GET_CLASS(node)->get_xmlNode(node, lasso_dump);
	node_data = lasso_legacy_get_signature_node_data(node, NULL);
	context = lasso_node_get_signature(node);
	/* support for legacy way to put a signature on a node */
	if (! lasso_validate_signature_context(context)) {
		if (lasso_legacy_extract_and_copy_signature_parameters(node, node_data))
			context = lasso_node_get_signature(node);
	}
	if (! lasso_dump && node_data && xmlnode && lasso_validate_signature_context(context)) {
		int rc;
		char *id_attribute = G_STRUCT_MEMBER(char*, node,
				node_data->id_attribute_offset);

		rc = lasso_sign_node(xmlnode, context, node_data->id_attribute_name,
				id_attribute);
		if (rc != 0) {
			warning("Signing of %s:%s failed: %s", xmlnode->ns->prefix,
					xmlnode->name, lasso_strerror(rc));
			lasso_release_xml_node(xmlnode);
		}
	}

	return xmlnode;
}

/**
 * lasso_node_cleanup_original_xmlnodes:
 *
 * @node: a #LassoNode
 *
 * Traverse the #LassoNode tree starting at Node and remove keeped xmlNode if one is found.
 *
 * Return value: None
 */
void
lasso_node_cleanup_original_xmlnodes(LassoNode *node)
{
	lasso_node_traversal(node, lasso_node_remove_original_xmlnode, 0);
}

static GQuark original_xmlnode_quark;
static GQuark custom_element_quark;

/**
 * lasso_node_get_original_xmlnode:
 * @node: a #LassoNode
 *
 * Retrieve the original xmlNode eventually associated to this #LassoNode.
 *
 * Return value:(transfer none): an #xmlNodePtr or NULL.
 */
xmlNodePtr
lasso_node_get_original_xmlnode(LassoNode *node)
{
	return g_object_get_qdata(G_OBJECT(node), original_xmlnode_quark);
}

static void original_xmlnode_free(void *node) {
	xmlNode *xnode = (xmlNode*)node;


	if (node) {
		if (lasso_flag_memory_debug) {
			fprintf(stderr, "freeing original xmlnode %s (at %p)\n", xnode->name, xnode);
		}
		xmlFreeNode(xnode);
	}
}

/**
 * lasso_node_set_original_xmlnode:
 * @node: the #LassoNode object
 * @xmlnode: an #xmlNode
 *
 * Set the underlying XML representation of the object.
 *
 */
void
lasso_node_set_original_xmlnode(LassoNode *node, xmlNode* xmlnode)
{
	if (xmlnode) {
		xmlNode *copy = NULL;
		xmlNode *parent = xmlnode->parent;

		copy = xmlCopyNode(xmlnode, 1);
		/* excl-c14n can move some namespace declarations at the point where the document is
		 * cut, to simulate it we copy on the new node all namespaces from the parents of
		 * the node which are not shadowed by another declaration on this node or one of its
		 * parent. */
		while (parent && parent->type == XML_ELEMENT_NODE) {
			xmlNs *ns_def = parent->nsDef;
			xmlNs *local_ns_def;
			while (ns_def) {
				int ok = 1;
				local_ns_def = copy->nsDef;
				while (local_ns_def) {
					if (lasso_strisequal((char*)local_ns_def->prefix, (char*)ns_def->prefix)) {
						ok = 0;
						break;
					}
					local_ns_def = local_ns_def->next;
				}
				if (ok) {
					xmlNewNs(copy, ns_def->href, ns_def->prefix);
				}
				ns_def = ns_def->next;
			}
			parent = parent->parent;
		}

		if (lasso_flag_memory_debug) {
			fprintf(stderr, "setting original xmlnode (at %p) on node %s:%p\n", copy, G_OBJECT_TYPE_NAME (node), node);
		}
		g_object_set_qdata_full(G_OBJECT(node), original_xmlnode_quark, copy, (GDestroyNotify)original_xmlnode_free);
	} else {
		if (lasso_flag_memory_debug) {
			fprintf(stderr, "clearing original xmlnode on node %p\n", node);
		}
		g_object_set_qdata_full(G_OBJECT(node), original_xmlnode_quark, NULL, (GDestroyNotify)original_xmlnode_free);
	}
}

struct _CustomElement {
	char *prefix;
	char *href;
	char *nodename;
	GHashTable *namespaces;
	LassoSignatureContext signature_context;
	xmlSecKey *encryption_public_key;
	LassoEncryptionSymKeyType encryption_sym_key_type;
};

static struct _CustomElement *
_lasso_node_new_custom_element()
{
	struct _CustomElement *ret = g_new0(struct _CustomElement, 1);
	ret->namespaces = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	return ret;
}

static void
_lasso_node_free_custom_element(struct _CustomElement *custom_element)
{
	if (custom_element) {
		lasso_release_string(custom_element->prefix);
		lasso_release_string(custom_element->href);
		lasso_release_string(custom_element->nodename);
		lasso_release_ghashtable(custom_element->namespaces);
		lasso_release_sec_key(custom_element->encryption_public_key);
		lasso_release_sec_key(custom_element->signature_context.signature_key);
	}
	lasso_release(custom_element);
}

/**
 * _lasso_node_get_custom_element:
 * @node: a #LassoNode object
 *
 * Return the eventually attached custom namespace object
 *
 * Return value: NULL or an #_CustomElement structure.
 */
static struct _CustomElement*
_lasso_node_get_custom_element(LassoNode *node)
{
	if (! LASSO_NODE(node))
		return NULL;
	return g_object_get_qdata((GObject*)node, custom_element_quark);
}

static struct _CustomElement*
_lasso_node_get_custom_element_or_create(LassoNode *node)
{
	struct _CustomElement *custom_element;

	if (! LASSO_IS_NODE(node))
		return NULL;

	custom_element = _lasso_node_get_custom_element(node);
	if (! custom_element) {
		custom_element = _lasso_node_new_custom_element();
		g_object_set_qdata_full((GObject*)node, custom_element_quark,
				custom_element,
				(GDestroyNotify)_lasso_node_free_custom_element);
	}
	return custom_element;
}


/**
 * lasso_node_set_custom_namespace:
 * @node: a #LassoNode object
 * @prefix: the prefix to use for the definition
 * @href: the URI of the namespace
 *
 * Set a custom namespace for an object instance, use it with object existing a lot of revision of
 * the nearly same namespace.
 */
void
lasso_node_set_custom_namespace(LassoNode *node, const char *prefix, const char *href)
{
	struct _CustomElement *custom_element;

	custom_element = _lasso_node_get_custom_element_or_create(node);
	g_return_if_fail (custom_element != NULL);

	lasso_assign_string(custom_element->prefix, prefix);
	lasso_assign_string(custom_element->href, href);
}

/**
 * lasso_node_set_signature:
 * @node: a #LassoNode object
 * @signature_context: a #LassoSignatureContext structure
 *
 * Setup a signature on @node.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_node_set_signature(LassoNode *node, LassoSignatureContext context)
{
	struct _CustomElement *custom_element;
	int rc = 0;

	lasso_bad_param(NODE, node);
	custom_element = _lasso_node_get_custom_element_or_create(node);
	g_return_val_if_fail (custom_element != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (custom_element->signature_context.signature_key) {
		lasso_release_sec_key(custom_element->signature_context.signature_key);
	}
	custom_element->signature_context.signature_method = context.signature_method;
	lasso_assign_new_sec_key(custom_element->signature_context.signature_key,
			context.signature_key);
	return rc;
}

/**
 * lasso_node_get_signature:
 * @node: a #LassoNode object
 * @type: an output for the signature type
 * @method: an output for the signature method
 * @private_key: an output for the private key
 * @private_key_password: an output for the private key password
 * @certificate: an output for the certificate
 *
 * Return signature parameters stored with this node.
 */
LassoSignatureContext
lasso_node_get_signature(LassoNode *node)
{
	struct _CustomElement *custom_element;

	g_return_val_if_fail (LASSO_IS_NODE(node), LASSO_SIGNATURE_CONTEXT_NONE);
	custom_element = _lasso_node_get_custom_element(node);
	if (! custom_element) {
		return LASSO_SIGNATURE_CONTEXT_NONE;
	}
	return custom_element->signature_context;
}

/**
 * lasso_node_set_encryption:
 * @node: a @LassoNode object
 * @encryption_public_key: an #xmlSecKey used to crypt the session key
 * @encryption_sym_key_type: the kind of session key to use
 *
 * Setup a node for future encryption. It is read by saml2:EncryptedElement for eventually
 * encrypting nodes.
 *
 * Return value: 0 if successful, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if node is not a
 * #LassoNode.
 */
void
lasso_node_set_encryption(LassoNode *node, xmlSecKey *encryption_public_key,
		LassoEncryptionSymKeyType encryption_sym_key_type)
{
	struct _CustomElement *custom_element;

	g_return_if_fail(LASSO_IS_NODE(node));
	if (encryption_public_key) {
		custom_element = _lasso_node_get_custom_element_or_create(node);
		if (! custom_element) {
			return;
		}
	} else {
		custom_element = _lasso_node_get_custom_element(node);
		if (! custom_element) {
			return;
		}
		lasso_release_sec_key(custom_element->encryption_public_key);
		return;
	}
	lasso_assign_sec_key(custom_element->encryption_public_key,
			encryption_public_key);
	if (encryption_sym_key_type < LASSO_ENCRYTPION_SYM_KEY_TYPE_LAST) {
		custom_element->encryption_sym_key_type = encryption_sym_key_type;
	} else {
		custom_element->encryption_sym_key_type = LASSO_ENCRYPTION_SYM_KEY_TYPE_DEFAULT;
	}
}

/**
 * lasso_node_get_encryption:
 * @node: a #LassoNode object
 * @encryption_public_key_ptr: a pointer on a pointer to an #xmlSecKey object, to hold the the
 * public key used to encrypt the session key
 * @encryption_sym_key_type: a pointer on a #LassoEncryptionSymKeyType
 *
 * Lookup eventual configuration for encrypting the given node.
 */
void
lasso_node_get_encryption(LassoNode *node, xmlSecKey **encryption_public_key,
		LassoEncryptionSymKeyType *encryption_sym_key_type)
{
	struct _CustomElement *custom_element;

	g_return_if_fail(LASSO_IS_NODE(node));
	custom_element = _lasso_node_get_custom_element(node);
	if (custom_element && custom_element->encryption_public_key) {
		lasso_assign_sec_key(*encryption_public_key,
				custom_element->encryption_public_key);
		*encryption_sym_key_type = custom_element->encryption_sym_key_type;
	}
}

/**
 * lasso_node_set_custom_nodename:
 * @node: a #LassoNode object
 * @nodename: the name to use for the node
 *
 * Set a custom nodename for an object instance, use it with object implement a schema type and not
 * a real element.
 */
void
lasso_node_set_custom_nodename(LassoNode *node, const char *nodename)
{
	struct _CustomElement *custom_element;

	custom_element = _lasso_node_get_custom_element_or_create(node);
	g_return_if_fail (custom_element != NULL);

	lasso_assign_string(custom_element->nodename, nodename);
}

/**
 * lasso_node_add_custom_namespace:
 * @prefix: prefix name
 * @href: href url
 *
 * Add a custom namespace declaration at this node level
 */
void
lasso_node_add_custom_namespace(LassoNode *node, const char *prefix,
		const char *href)
{
	struct _CustomElement *custom_element;

	custom_element = _lasso_node_get_custom_element_or_create(node);
	g_return_if_fail(custom_element != NULL);

	g_hash_table_insert(custom_element->namespaces, g_strdup(prefix), g_strdup(href));
}

/*****************************************************************************/
/* implementation methods                                                    */
/*****************************************************************************/

static void
lasso_node_remove_original_xmlnode(LassoNode *node, SnippetType type) {
	LassoNodeClass *class;
	class = LASSO_NODE_GET_CLASS(node);

	if (class->node_data->keep_xmlnode || type & SNIPPET_KEEP_XMLNODE) {
		lasso_node_set_original_xmlnode(node, NULL);
	}
}

static void
lasso_node_traversal(LassoNode *node, void (*do_to_node)(LassoNode *node, SnippetType type), SnippetType type) {
	LassoNodeClass *class;
	struct XmlSnippet *snippet;

	if (node == NULL || do_to_node == NULL) {
		return;
	}
	class = LASSO_NODE_GET_CLASS(node);
	do_to_node(node, type);

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		GType g_type = G_TYPE_FROM_CLASS(class);
		snippet = class->node_data->snippets;
		while (snippet->name != NULL) {
			SnippetType type;
			void **value = SNIPPET_STRUCT_MEMBER_P(node, g_type, snippet);

			type = snippet->type & 0xff;
			switch (type) {
				case SNIPPET_NODE:
				case SNIPPET_NODE_IN_CHILD:
					lasso_node_traversal(*value, do_to_node, snippet->type);
					break;
				case SNIPPET_LIST_NODES:
					{
						GList *list = *value;
						while (list != NULL) {
							if (list->data) {
								lasso_node_traversal(LASSO_NODE(list->data), do_to_node, snippet->type);
							}
							list = g_list_next(list);
						}
					}
					break;
				case SNIPPET_UNUSED1:
					g_assert_not_reached();
				default:
					break;
			}
			snippet++;
		}
		class = g_type_class_peek_parent(class);
	}
}

static void
lasso_node_impl_destroy(LassoNode *node)
{
	g_object_unref(G_OBJECT(node));
}
#define trace_snippet(format, args...) \
	lasso_trace(format "%s.%s\n", ## args, G_OBJECT_TYPE_NAME(node), snippet->name)

/**
 * _lasso_node_collect_namespaces:
 * @namespaces: a pointer to a pointer on a #GHashTable
 * @node: an #xmlNode pointer
 *
 * Follow the parent link of the @node to collect all declared namespaces, it is usefull for content
 * that need to be interpreted with respect to declared namespaces (XPath for example).
 */
void
_lasso_node_collect_namespaces(GHashTable **namespaces, xmlNode *node)
{
	if (*namespaces == NULL) {
		*namespaces = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);
	}
	while (node) {
		if (node->type == XML_ELEMENT_NODE) {
			xmlNs *nsDef = node->nsDef;
			while (nsDef) {
				if (nsDef->prefix && nsDef->href) {
					g_hash_table_insert(*namespaces, g_strdup((char*)nsDef->prefix),
							g_strdup((char*)nsDef->href));
				}
				nsDef = nsDef->next;
			}
		}
		node = node->parent;
	}
}

gboolean
lasso_get_integer_attribute(xmlNode *node, xmlChar *attribute_name, xmlChar *ns_href, int *integer, long int low, long int high) {
	xmlChar *content = NULL;
	gboolean rc = FALSE;
	long int what;

	g_assert (integer);
	content = xmlGetNsProp(node, attribute_name, ns_href);
	if (! content)
		goto cleanup;
	if (! lasso_string_to_xsd_integer((char*)content, &what))
		goto cleanup;
	if (what < low || what >= high)
		goto cleanup;
	*integer = what;
	rc = TRUE;
cleanup:
	lasso_release_xml_string(content);
	return rc;
}

static inline gboolean
lasso_equal_namespace(xmlNs *t1, xmlNs *t2) {
	return t1 && t2 && (t1 == t2 ||
			lasso_strisequal((char*)t1->href, (char*)t2->href));
}

static void
snippet_set_value(LassoNode *node, LassoNodeClass *class, struct XmlSnippet *snippet, xmlChar *content) {
	void *value;
	GType g_type = G_TYPE_FROM_CLASS(class);

	/* If not offset, it means it is handled by an adhoc init_from_xml */
	if (! snippet->offset && ! (snippet->type & SNIPPET_PRIVATE)) {
		return;
	}
	value = SNIPPET_STRUCT_MEMBER_P(node, g_type, snippet);
	if (snippet->type & SNIPPET_INTEGER) {
		int val = strtol((char*)content, NULL, 10);
		if (((val == INT_MIN || val == INT_MAX) && errno == ERANGE)
				|| errno == EINVAL || val < 0) {
			if (snippet->type & SNIPPET_OPTIONAL_NEG) {
				val = -1;
			} else {
				val = 0;
			}
		}
		(*(int*)value) = val;
	} else if (snippet->type & SNIPPET_BOOLEAN) {
		int val = 0;
		if (strcmp((char*)content, "true") == 0) {
			val = 1;
		} else if (strcmp((char*)content, "1") == 0) {
			val = 1;
		}
		(*(int*)value) = val;
	} else {
		lasso_assign_string((*(char**)value), (char*)content);
		if (lasso_flag_memory_debug == TRUE) {
			fprintf(stderr, "   setting prop %s/%s to value %p: %s\n",
					G_OBJECT_TYPE_NAME(node), snippet->name, *(void**)value, (char*)content);
		}
	}
}

gboolean
next_node_snippet(GSList **class_iter_p, struct XmlSnippet **snippet_p)
{
	while (*class_iter_p) {
		if (*snippet_p) {
			if ((*snippet_p)->name) {
				SnippetType type = (*snippet_p)->type;
				/* special case for ArtifactResponse */
				if (type & SNIPPET_ANY && (type & 0xff) == SNIPPET_NODE)
					return TRUE;
				if (! (type & SNIPPET_ANY) && (*snippet_p)->name[0] != '\0') {
					switch (type & 0xff) {
						case SNIPPET_NODE:
						case SNIPPET_NODE_IN_CHILD:
						case SNIPPET_LIST_XMLNODES:
						case SNIPPET_LIST_CONTENT:
						case SNIPPET_LIST_NODES:
						case SNIPPET_EXTENSION:
						case SNIPPET_XMLNODE:
						case SNIPPET_CONTENT:
						case SNIPPET_SIGNATURE:
							return TRUE;
						default:
							break;
					}
				}
				++*snippet_p;
			} else {
				*class_iter_p = g_slist_next(*class_iter_p);
				*snippet_p = NULL;
			}
		} else {
			*snippet_p = ((LassoNodeClass*)(*class_iter_p)->data)
						->node_data->snippets;
		}
	}
	return FALSE;
}

static inline gboolean
is_snippet_type(struct XmlSnippet *snippet, SnippetType simple_type) {
	return (snippet->type & 0xff) == simple_type;
}

static inline gboolean
is_snippet_mandatory(struct XmlSnippet *snippet)
{
	return snippet->type & SNIPPET_MANDATORY ? TRUE : FALSE;
}

static inline gboolean
is_snippet_multiple(struct XmlSnippet *snippet)
{
	switch (snippet->type & 0xff) {
		case SNIPPET_LIST_XMLNODES:
		case SNIPPET_LIST_CONTENT:
		case SNIPPET_LIST_NODES:
		case SNIPPET_EXTENSION:
			return TRUE;
		default:
			return FALSE;
	}
}

static inline gboolean
node_match_snippet(xmlNode *parent, xmlNode *node, struct XmlSnippet *snippet)
{
	gboolean rc = TRUE;

	/* special case of ArtifactResponse */
	if (snippet->type & SNIPPET_ANY) {
		return TRUE;
	} else {
		rc = rc && lasso_strisequal(snippet->name, (char*)node->name);
		rc = rc &&
		    ((!snippet->ns_uri &&
			lasso_equal_namespace(parent->ns, node->ns)) ||
		    (node->ns &&
		           lasso_strisequal((char*)node->ns->href, snippet->ns_uri)));
		return rc;
	}
}

/** FIXME: return a real error code */
static int
lasso_node_impl_init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	struct XmlSnippet *snippet;
	xmlNode *t;
	LassoNodeClass *class;
	void *value;
	SnippetType type;
	struct XmlSnippet *snippet_any = NULL;
	struct XmlSnippet *snippet_any_attribute = NULL;
	GType g_type_collect_namespaces = 0, g_type_any = 0, g_type_any_attribute = 0;
	struct XmlSnippet *snippet_collect_namespaces = NULL;
	struct XmlSnippet *snippet_signature = NULL;
	gboolean keep_xmlnode = FALSE;
	GSList *class_list = NULL;
	GSList *class_iter = NULL;
	xmlAttr *attr = NULL;
	GType g_type = 0;
	LassoNodeClass *node_class;
	gint rc = 0;

	if (! xmlnode) {
		rc = 1;
		goto cleanup;
	}

	node_class = class = LASSO_NODE_GET_CLASS(node);
	/* No node_data no initialization possible */
	if (! class->node_data) {
		message(G_LOG_LEVEL_WARNING, "Class %s has no node_data so no initialization "
				"is possible", G_OBJECT_CLASS_NAME(class));
		rc = 1;
		goto cleanup;
	}

	/* Collect special snippets like SNIPPET_COLLECT_NAMESPACES, SNIPPET_ANY, SNIPPET_ATTRIBUTE
	 * or SNIPPET_SIGNATURE, and initialize class_list in reverse. */
	while (class && LASSO_IS_NODE_CLASS(class)) {
		if (class->node_data) {
			GType g_type = G_TYPE_FROM_CLASS(class);
			keep_xmlnode |= class->node_data->keep_xmlnode;
			if (class->node_data->snippets)
				class_list = g_slist_prepend(class_list, class);
			for (snippet = class->node_data->snippets; snippet && snippet->name; snippet++) {
				type = snippet->type & 0xff;

				if (snippet->name && snippet->name[0] == '\0' && type ==
						SNIPPET_COLLECT_NAMESPACES) {
					snippet_collect_namespaces = snippet;
					g_type_collect_namespaces = g_type;
				} else if (type == SNIPPET_SIGNATURE) {
					snippet_signature = snippet;
				} else if (type == SNIPPET_ATTRIBUTE && snippet->type & SNIPPET_ANY) {
					g_type_any_attribute = g_type;
					snippet_any_attribute = snippet;
				} else if (type == SNIPPET_TEXT_CHILD) {
					xmlChar *tmp = xmlNodeGetContent(xmlnode);
					snippet_set_value(node, class, snippet, tmp);
					lasso_release_xml_string(tmp);
				} else if (type != SNIPPET_ATTRIBUTE && type != SNIPPET_NODE && snippet->type & SNIPPET_ANY) {
					if (! snippet_any) {
						g_type_any = g_type;
						snippet_any = snippet;
					} else {
						critical("Two any node snippet for class %s",
								g_type_name(G_TYPE_FROM_INSTANCE(node)));
					}
				}
			}
		}
		class = g_type_class_peek_parent(class);
	}

	/* If any class asked for keeping the xmlNode, keep it around */
	if (keep_xmlnode) {
		lasso_node_set_original_xmlnode(node, xmlnode);
	}

	/** Collect attributes */
	for (attr = xmlnode->properties; attr; attr = attr->next) {
		xmlChar *content;
		content = xmlNodeGetContent((xmlNode*)attr);
		int ok = 0;

		/* Skip xsi:type if it was used to find the node class */
		if (attr->ns && lasso_strisequal((char*)attr->name, "type") &&
				lasso_strisequal((char*)attr->ns->href, LASSO_XSI_HREF)) {
			char *colon = strchr((char*)content, ':');
			if (colon) {
				xmlNs *ns;
				*colon = '\0';
				ns = xmlSearchNs(NULL, xmlnode, content);
				*colon = ':';
				if (ns && lasso_strisequal((char*)ns->href, (char*)node_class->node_data->ns->href)
						&& lasso_strisequal(&colon[1], node_class->node_data->node_name)) {
					lasso_release_xml_string(content);
					continue;
				}
			}
		}

		for (class_iter = class_list; class_iter; class_iter = class_iter->next) {
			class = class_iter->data;
			for (snippet = class->node_data->snippets;
					snippet && snippet->name; snippet++) {
				type = snippet->type & 0xff;
				/* assign attribute content if attribute has the same name as the
				 * snippet and:
				 * - the snippet and the attribute have no namespace
				 * - the snippet has no namespace but the attribute has the same
				 *   namespace as the node
				 * - the snippet and the node have a namespace, which are equal.
				 */
				if (type != SNIPPET_ATTRIBUTE)
					continue;
				if (! lasso_strisequal((char*)attr->name, (char*)snippet->name))
					continue;
				if (attr->ns) {
					gboolean same_namespace, given_namespace;

					same_namespace = lasso_equal_namespace(attr->ns,
							xmlnode->ns) && ! snippet->ns_uri;
					given_namespace = snippet->ns_uri &&
						lasso_strisequal((char*)attr->ns->href,
								snippet->ns_uri);
					if (! same_namespace && ! given_namespace)
						break;
				}
				snippet_set_value(node, class, snippet, content);
				ok = 1;
				break;
			}
		}
		if (! ok && attr->ns && snippet_any_attribute) {
			GHashTable **any_attribute;
			gchar *key;

			any_attribute = SNIPPET_STRUCT_MEMBER_P(node, g_type_any_attribute,
					snippet_any_attribute);
			if (*any_attribute == NULL) {
				*any_attribute = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, g_free);
			}
			if (lasso_equal_namespace(attr->ns, xmlnode->ns)) {
				key = g_strdup((char*)attr->name);
			} else {
				key = g_strdup_printf("{%s}%s", attr->ns->href, attr->name);
			}
			g_hash_table_insert(*any_attribute, key, g_strdup((char*)content));
			lasso_release_xml_string(content);
		} else if (! ok) {
			warning("lasso_node_impl_init_from_xml: Unexpected attribute: {%s}%s = %s",
					attr->ns ? attr->ns->href : NULL, attr->name, content);
		}
		lasso_release_xml_string(content);
	}

	/* Collect children nodes in reverse order of class parents (older parent first), skip non
	 * node and ANY snippets) */
	class_iter = class_list;
	snippet = ((LassoNodeClass*)class_iter->data)->node_data->snippets;
	next_node_snippet(&class_iter, &snippet);
	for (t = xmlnode->children; t && class_iter && snippet; t = t->next) {
		/* Only collect text node if:
		 * - there is a LIST_XMLNODES any snippet
		 * - there is a LIST_NODES any snippet with the ALLOW_TEXT modifier
		 */
		if (t->type == XML_TEXT_NODE && snippet_any &&
				(is_snippet_type(snippet_any, SNIPPET_LIST_XMLNODES)
				 || (is_snippet_type(snippet_any, SNIPPET_LIST_NODES) &&
					 (snippet_any->type & SNIPPET_ALLOW_TEXT)))) {
			GList **location = SNIPPET_STRUCT_MEMBER_P(node, g_type_any, snippet_any);
			if (is_snippet_type(snippet_any, SNIPPET_LIST_XMLNODES)) {
				lasso_list_add_xml_node(*location, t);
			} else {
				lasso_list_add_new_gobject(*location,
						lasso_node_new_from_xmlNode_with_type(t,
							"LassoMiscTextNode"));
			}
		} else if (t->type == XML_COMMENT_NODE || t->type == XML_PI_NODE || t->type == XML_TEXT_NODE) {
			/* ignore comments */
			continue;
		} else if (t->type == XML_ELEMENT_NODE) {
			LassoNode *subnode = NULL;
			xmlNode *first_child = NULL;
			GList **list = NULL;
			xmlChar *content = NULL;
			gboolean match = FALSE;
			struct XmlSnippet *matched_snippet = NULL;

#define ADVANCE_MATCH \
				if (snippet->type & SNIPPET_JUMP_ON_MATCH) { \
					snippet += (ptrdiff_t)SNIPPET_JUMP_OFFSET(snippet->type); \
				}  else { \
					snippet++; \
				} \
				next_node_snippet(&class_iter, &snippet);
#define ADVANCE_MISS \
				if (snippet->type & SNIPPET_JUMP_ON_MISS) { \
					snippet += (ptrdiff_t)SNIPPET_JUMP_OFFSET(snippet->type); \
				}  else { \
					snippet++; \
				} \
				next_node_snippet(&class_iter, &snippet);
#define ERROR \
				error("Element %s:%s cannot be parsed", \
						t->ns != NULL ? (char*)t->ns->prefix : "<noprefix>", \
						t->name); \
				rc = 1; \
				goto cleanup;
			/* Find a matching snippet */
			while (class_iter && snippet) {
				gboolean mandatory = is_snippet_mandatory(snippet);
				gboolean multiple = is_snippet_multiple(snippet);

				if ((match = node_match_snippet(xmlnode, t, snippet))) {
					matched_snippet = snippet;
					class = class_iter->data;
					g_type = G_TYPE_FROM_CLASS(class);
					value = SNIPPET_STRUCT_MEMBER_P(node, g_type, snippet);
					list = value;
					if (! multiple || (snippet->type & SNIPPET_JUMP_ON_MATCH)) {
						ADVANCE_MATCH;
					}
					break;
				} else {
					if (mandatory) {
						break;
					} else {
						ADVANCE_MISS;
					}
				}
			}
			if (! match) {
				ERROR;
			}
#undef ADVANCE
#undef ERROR

			if (matched_snippet->offset || (matched_snippet->type & SNIPPET_PRIVATE)) {
				switch (matched_snippet->type & 0xff) {
					case SNIPPET_LIST_NODES:
					case SNIPPET_NODE:
						subnode = lasso_node_new_from_xmlNode_with_type(t,
								matched_snippet->class_name);
						if (is_snippet_type(matched_snippet, SNIPPET_NODE)) {
							lasso_assign_new_gobject(*(LassoNode**)value, subnode);
						} else {
							lasso_list_add_new_gobject(*list, subnode);
						}
						break;
					case SNIPPET_NODE_IN_CHILD:
						first_child = xmlSecGetNextElementNode(t->children);
						if (first_child) {
							subnode = lasso_node_new_from_xmlNode_with_type(first_child,
										matched_snippet->class_name);
							lasso_assign_new_gobject(*(LassoNode**)value, subnode);
						}
						break;
					case SNIPPET_XMLNODE:
						lasso_assign_xml_node(*(xmlNode**)value, t);
						break;
					case SNIPPET_LIST_XMLNODES:
					case SNIPPET_EXTENSION:
						lasso_list_add_xml_node(*list, t);
						break;
					case SNIPPET_CONTENT:
					case SNIPPET_LIST_CONTENT:
						content = xmlNodeGetContent(t);
						if (is_snippet_type(matched_snippet, SNIPPET_CONTENT)) {
							snippet_set_value(node, class, matched_snippet, content);
						} else { /* only list of string-like xsd:type supported */
							lasso_list_add_string(*list, (char*)content);
						}
						lasso_release_xml_string(content);
						break;
					case SNIPPET_SIGNATURE:
						/* We ignore it */
						break;
					default:
						g_assert_not_reached();

				}
			}
			/* When creating a new LassoNode and option KEEP_XMLNODE is present,
			 * we attached the xmlNode to the LassoNode */
			if (subnode && (matched_snippet->type & SNIPPET_KEEP_XMLNODE)) {
				lasso_node_set_original_xmlnode(subnode, t);
			}
		} else {
			g_assert_not_reached();
		}
	}
	if (t) { /* t is an ELEMENT that dont match any snippet, when taken in order */
		if (snippet_any && is_snippet_type(snippet_any, SNIPPET_LIST_XMLNODES)) {
			value = SNIPPET_STRUCT_MEMBER_P(node, g_type_any, snippet_any);
			GList **list = value;
			for (; t; t = t->next) {
				lasso_list_add_xml_node(*list, t);
			}
		} else if (snippet_any && is_snippet_type(snippet_any, SNIPPET_LIST_NODES)) {
			value = SNIPPET_STRUCT_MEMBER_P(node, g_type_any, snippet_any);
			GList **list = value;
			for (; t; t = t->next) {
				LassoNode *subnode = NULL;

				if (t->type == XML_TEXT_NODE && (snippet_any->type &
							SNIPPET_ALLOW_TEXT)) {
					lasso_list_add_new_gobject(*list,
							lasso_node_new_from_xmlNode_with_type(t,
								"LassoMiscTextNode"));
				} else if (t->type == XML_ELEMENT_NODE) {
					subnode = lasso_node_new_from_xmlNode_with_type(t,
							snippet_any->class_name);
					if (subnode && (snippet_any->type & SNIPPET_KEEP_XMLNODE)) {
						lasso_node_set_original_xmlnode(subnode, t);
					}
					if (! subnode) {
						subnode = (LassoNode*)
							lasso_misc_text_node_new_with_xml_node(t);
					}
					lasso_list_add_new_gobject(*list, subnode);
				}
			}
		} else if (snippet_any) {
			g_assert_not_reached();
		} else {
			for (; t; t = t->next) {
				if (t->type == XML_ELEMENT_NODE) {
					critical("lasso_node_impl_init_from_xml: Cannot match "
							"element {%s}%s with a snippet of "
							"class %s",
							t->ns ?  t->ns->href : NULL, t->name,
							g_type_name(G_TYPE_FROM_INSTANCE(node)));
					rc = 1;
					goto cleanup;
				}
			}
		}
	}

	/* Collect namespaces on the current node */
	if (snippet_collect_namespaces) {
		void *value = SNIPPET_STRUCT_MEMBER_P(node, g_type_collect_namespaces,
				snippet_collect_namespaces);
		_lasso_node_collect_namespaces(value, xmlnode);
	}

	/* Collect signature parameters */
	{
			LassoSignatureMethod method = 0;
			xmlChar *private_key = NULL;
			xmlChar *private_key_password = NULL;
			xmlChar *certificate = NULL;
			LassoSignatureContext signature_context = LASSO_SIGNATURE_CONTEXT_NONE;

		while (snippet_signature) {
			int what;
			if (! lasso_get_integer_attribute(xmlnode, LASSO_SIGNATURE_METHOD_ATTRIBUTE,
						BAD_CAST LASSO_LIB_HREF, &what,
						LASSO_SIGNATURE_METHOD_RSA_SHA1,
						LASSO_SIGNATURE_METHOD_LAST))
				break;
			method = what;
			if (! lasso_get_integer_attribute(xmlnode, LASSO_SIGNATURE_METHOD_ATTRIBUTE,
					BAD_CAST LASSO_LIB_HREF, &what, LASSO_SIGNATURE_TYPE_NONE+1,
					LASSO_SIGNATURE_TYPE_LAST))
				break;
			private_key_password = xmlGetNsProp(xmlnode, LASSO_PRIVATE_KEY_PASSWORD_ATTRIBUTE,
				BAD_CAST LASSO_LIB_HREF);
			if (! private_key)
				break;
			private_key = xmlGetNsProp(xmlnode, LASSO_PRIVATE_KEY_ATTRIBUTE, BAD_CAST
				LASSO_LIB_HREF);
			certificate = xmlGetNsProp(xmlnode, LASSO_CERTIFICATE_ATTRIBUTE, BAD_CAST
				LASSO_LIB_HREF);

			signature_context.signature_method = method;
			signature_context.signature_key = lasso_xmlsec_load_private_key((char*) private_key,
					(char*) private_key_password, method, (char*) certificate);
			lasso_node_set_signature(node, signature_context);
			break;
		}
		lasso_release_xml_string(private_key);
		lasso_release_xml_string(private_key_password);
		lasso_release_xml_string(certificate);
	}
cleanup:
	lasso_release_slist(class_list);
	return rc;
}
#undef trace_snippet

/**
 * lasso_node_remove_signature:
 * @node: a #LassoNode object
 *
 * Remove any signature setup on this node.
 */
void
lasso_node_remove_signature(LassoNode *node) {
       LassoNodeClass *klass;

       if (! LASSO_IS_NODE(node))
               return;
       klass = LASSO_NODE_GET_CLASS(node);
       /* follow the class parenting chain */
       while (klass && LASSO_IS_NODE_CLASS(klass)) {
               if (klass && klass->node_data && klass->node_data->sign_type_offset != 0) {
                       G_STRUCT_MEMBER(LassoSignatureType, node, klass->node_data->sign_type_offset) =
                               LASSO_SIGNATURE_TYPE_NONE;
               }
               klass = g_type_class_peek_parent(klass);
       }
       lasso_node_set_signature(node, LASSO_SIGNATURE_CONTEXT_NONE);
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static void
_xmlnode_add_custom_namespace(const char *prefix, const char *href, xmlNode *xmlnode)
{
	xmlNs *existing = NULL;

	existing = xmlSearchNs(NULL, xmlnode, BAD_CAST prefix);
	if (existing) {
		if (lasso_strisnotequal((char *)existing->href,href)) {
			message(G_LOG_LEVEL_CRITICAL, "Cannot add namespace %s='%s' to node %s, "
					"namespace already exists with another href", prefix, href,
					(char*)xmlnode->name);
		}
		return;
	}
	xmlNewNs(xmlnode, BAD_CAST href, BAD_CAST prefix);
}

static char*
lasso_node_impl_build_query(LassoNode *node)
{
	return lasso_node_build_query_from_snippets(node);
}

static xmlNode*
lasso_node_impl_get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
	LassoNodeClass *version_class = NULL;
	xmlNode *xmlnode;
	xmlNs *ns = NULL;
	GSList *list_classes = NULL, *iter_classes = NULL;
	LassoNode *value_node;
	struct XmlSnippet *version_snippet;
	struct _CustomElement *custom_element;
	LassoNodeClass *xsi_sub_type_data_class = NULL;
	LassoNodeClass *node_name_class = class;

	while (node_name_class->node_data->xsi_sub_type) {
		node_name_class= g_type_class_peek_parent(node_name_class);
	}
	if (node_name_class != class) {
		xsi_sub_type_data_class = class;
	}
	g_assert(node_name_class && node_name_class->node_data &&
			node_name_class->node_data->node_name);

	/* Create node in its namespace */
	xmlnode = xmlNewNode(NULL, (xmlChar*)node_name_class->node_data->node_name);
	if (node_name_class->node_data->ns) {
		ns = get_or_define_ns(xmlnode, node_name_class->node_data->ns->href,
				node_name_class->node_data->ns->prefix);
		xmlSetNs(xmlnode, ns);
	}
	/* If subtype, set an xsi:type attribute */
	if (xsi_sub_type_data_class) {
		set_xsi_type(xmlnode,
				xsi_sub_type_data_class->node_data->ns->prefix,
				xsi_sub_type_data_class->node_data->ns->href,
				BAD_CAST xsi_sub_type_data_class->node_data->node_name);
	}
	custom_element = _lasso_node_get_custom_element(node);

	/* collect all classes in reverse order */
	while (class && LASSO_IS_NODE_CLASS(class)) {
		if (class->node_data && class->node_data->snippets)
			list_classes = g_slist_prepend(list_classes, class);
		class = g_type_class_peek_parent(class);
	}

	/* set a custom namespace if one is found */
	if (custom_element != NULL) {
		if (custom_element->href) {
			xmlChar *prefix = BAD_CAST (custom_element->prefix);
			xmlNs *ns = NULL, *oldns = NULL;

			oldns = xmlSearchNs(NULL, xmlnode, prefix);
			if (prefix && oldns) {
				prefix = NULL;
			}
			// remove existing default namespace
			if (prefix == NULL) {
				xmlNs *cur = xmlnode->nsDef, *last = NULL;
				while (cur) {
					if (cur->prefix == NULL) {
						if (last) {
							last->next = cur->next;
						} else {
							xmlnode->nsDef = cur->next;
						}
						xmlFreeNs(cur);
					}
					last = cur;
					cur = cur->next;
				}
			}
			ns = xmlNewNs(xmlnode, (xmlChar*)custom_element->href,
					(xmlChar*)custom_element->prefix);
			/* skip the base class namespace, it is replaced by the custom one */
			xmlSetNs(xmlnode, ns);
		}
		if (custom_element->nodename) {
			xmlNodeSetName(xmlnode, BAD_CAST (custom_element->nodename));
		}
		g_hash_table_foreach(custom_element->namespaces,
				(GHFunc)_xmlnode_add_custom_namespace, xmlnode);
	}


	for (iter_classes = list_classes; iter_classes; iter_classes = g_slist_next(iter_classes)) {
		class = iter_classes->data;
		lasso_node_build_xmlNode_from_snippets(node,
				(LassoNodeClass*)class, xmlnode,
				class->node_data->snippets,
				lasso_dump);
	}

	xmlCleanNs(xmlnode);

	/* backward compatibility with Liberty ID-FF 1.1; */
	if (find_path(node, "MajorVersion", &value_node, &version_class, &version_snippet) == TRUE) {
		int *value;
		int major_version, minor_version;

		value = SNIPPET_STRUCT_MEMBER_P(value_node, G_TYPE_FROM_CLASS(version_class),
				version_snippet);
		major_version = *value;

		if (find_path(node, "MinorVersion", &value_node, &version_class, &version_snippet) == TRUE) {
			value = SNIPPET_STRUCT_MEMBER_P(value_node, G_TYPE_FROM_CLASS(version_class),
					version_snippet);
			minor_version = *value;
		} else {
			minor_version = 0;
		}

		if (strcmp((char*)xmlnode->ns->href, LASSO_LIB_HREF) == 0) {
			if (major_version == 1 && minor_version == 0) {
				xmlFree((xmlChar*)xmlnode->ns->href); /* warning: discard const */
				xmlnode->ns->href = xmlStrdup((xmlChar*)
						"http://projectliberty.org/schemas/core/2002/12");
			}
		}
	}

	g_slist_free(list_classes);
	return xmlnode;
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static GObjectClass *parent_class = NULL;

static void
lasso_node_dispose(GObject *object)
{
	LassoNodeClass *class;
	struct XmlSnippet *snippet;
	SnippetType type;

	if (lasso_flag_memory_debug == TRUE) {
		fprintf(stderr, "dispose of %s (at %p)\n", G_OBJECT_TYPE_NAME(object), object);
	}

	class = LASSO_NODE_GET_CLASS(object);

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		for (snippet = class->node_data->snippets; snippet && snippet->name; snippet++) {
			void **value = SNIPPET_STRUCT_MEMBER_P(object, G_TYPE_FROM_CLASS(class), snippet);
			type = snippet->type & 0xff;

			if (! snippet->offset && ! (snippet->type & SNIPPET_PRIVATE))
				continue;
			if (snippet->type & SNIPPET_BOOLEAN)
				continue;
			if (snippet->type & SNIPPET_INTEGER)
				continue;

			if (*value == NULL)
				continue;

			if (lasso_flag_memory_debug == TRUE) {
				fprintf(stderr, "  freeing %s/%s (at %p)\n",
						G_OBJECT_TYPE_NAME(object), snippet->name, *value);
			}
			switch (type) {
				case SNIPPET_NODE:
				case SNIPPET_NODE_IN_CHILD:
					lasso_release_gobject(*value);
					break;
				case SNIPPET_XMLNODE:
					xmlFreeNode(*value);
					break;
				case SNIPPET_LIST_NODES:
					lasso_release_list_of_gobjects((*(GList**)value));
					break;
				case SNIPPET_EXTENSION:
				case SNIPPET_LIST_XMLNODES:
					lasso_release_list_of_xml_node(*(GList**)value);
					break;
				case SNIPPET_LIST_CONTENT:
					lasso_release_list_of_strings(*(GList**)value);
					break;
				case SNIPPET_CONTENT:
				case SNIPPET_TEXT_CHILD:
				case SNIPPET_ATTRIBUTE: {
								if (snippet->type & SNIPPET_ANY) {
									if (*value) {
										lasso_release_ghashtable(*value);
									}
								} else {
									lasso_release_string(*(char**)value);
								}
							} break;
				case SNIPPET_SIGNATURE:
							break; /* no real element here */
				case SNIPPET_COLLECT_NAMESPACES:
					if (*value) {
						lasso_release_ghashtable(*value);
					}
					break;
				default:
							fprintf(stderr, "%d\n", type);
							g_assert_not_reached();
			}

			if (type != SNIPPET_SIGNATURE) {
				/* Signature snippet is not something to free,
				 * so don't set the value to NULL */
				*value = NULL;
			}
		}
		class = g_type_class_peek_parent(class);
	}

	parent_class->dispose(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	return lasso_node_init_from_query_fields(node, query_fields);
}

static void
class_init(LassoNodeClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);

	parent_class = g_type_class_peek_parent(class);
	/* virtual public methods */
	class->destroy = lasso_node_impl_destroy;
	class->init_from_query = init_from_query;
	class->init_from_xml = lasso_node_impl_init_from_xml;

	/* virtual private methods */
	class->build_query = lasso_node_impl_build_query;
	class->get_xmlNode = lasso_node_impl_get_xmlNode;

	/* override */
	gobject_class->dispose = lasso_node_dispose;

	original_xmlnode_quark = g_quark_from_static_string("lasso_original_xmlnode");
	custom_element_quark = g_quark_from_static_string("lasso_custom_element");
	class->node_data = NULL;
}

static void
base_class_finalize(LassoNodeClass *class)
{
	if (class->node_data) {
		LassoNodeClassData *data = class->node_data;

		if (data->ns) {
			xmlFreeNs(data->ns);
		}
		if (data->node_name) {
			lasso_release(data->node_name);
		}
		lasso_release(class->node_data);
		class->node_data = NULL;
	}
}

GType
lasso_node_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoNodeClass),
			NULL,
			(GBaseFinalizeFunc) base_class_finalize,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoNode),
			0,
			NULL,
			NULL,
		};

		this_type = g_type_register_static(G_TYPE_OBJECT , "LassoNode", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_node_new:
 *
 * Creates a new #LassoNode.
 *
 * Return value: a newly created #LassoNode object
 **/
LassoNode*
lasso_node_new()
{
	return g_object_new(LASSO_TYPE_NODE, NULL);
}

/**
 * lasso_node_new_from_dump:
 * @dump: XML object dump
 *
 * Restores the @dump to a new #LassoNode subclass.
 *
 * Return value: a newly created object; or NULL if an error occured.
 **/
LassoNode*
lasso_node_new_from_dump(const char *dump)
{
	LassoNode *node;
	xmlDoc *doc;

	if (dump == NULL)
		return NULL;

	doc = lasso_xml_parse_memory(dump, strlen(dump));
	if (doc == NULL)
		return NULL;

	node = lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc));

	lasso_release_doc(doc);
	return node;
}


/**
 * lasso_node_new_from_soap:
 * @soap: the SOAP message
 *
 * Parses SOAP message and creates a new Lasso object with the right class.
 *
 * Return value: node if success; NULL otherwise
 **/
LassoNode*
lasso_node_new_from_soap(const char *soap)
{
	xmlDoc *doc;
	xmlNode *xmlnode;
	LassoNode *node = NULL;

	doc = lasso_xml_parse_memory(soap, strlen(soap));
	if (doc == NULL) {
		return NULL;
	}
	xmlnode = lasso_xml_get_soap_content(xmlDocGetRootElement(doc));
	if (xmlnode == NULL) {
		return NULL;
	}
	node = lasso_node_new_from_xmlNode(xmlnode);

	lasso_release_doc(doc);

	return node;
}

/* How finding a typename from an xmlNode works ?
 *
 * There is three way to get to a typename:
 * 1. by an xsi:type QName attribute, that we resolve
 * 2. by constructing a QName from the namespace of the xsi:type and the name of the node
 * 3. by resolving the QName of the node
 *
 * To resolve a typename you must map the QName using the default registry object, or use
 * prefix_from_href_and_nodename() to mat the QName to a prefix used to build the typename with this
 * template: typename = "Lasso" + prefix + name_part(QName).
 *
 * The resolving algorithm is in the function _type_name_from_href_and_nodename().
 *
 * The prefix extraction in prefix_from_href_and_nodename().
 *
 */
static const char *
prefix_from_href_and_nodename(const xmlChar *href, G_GNUC_UNUSED const xmlChar *nodename) {
	char *prefix = NULL;
#ifdef LASSO_WSF_ENABLED
	char *tmp = NULL;
#endif

	if (strcmp((char*)href, LASSO_LASSO_HREF) == 0)
		prefix = "";
	else if (strcmp((char*)href, LASSO_SAML_ASSERTION_HREF) == 0)
		prefix = "Saml";
	else if (strcmp((char*)href, LASSO_SAML_PROTOCOL_HREF) == 0)
		prefix = "Samlp";
	else if (strcmp((char*)href, LASSO_LIB_HREF) == 0)
		prefix = "Lib";
	else if (strcmp((char*)href, LASSO_SAML2_ASSERTION_HREF) == 0)
		prefix = "Saml2";
	else if (strcmp((char*)href, LASSO_SAML2_PROTOCOL_HREF) == 0)
		prefix = "Samlp2";
	else if (strcmp((char*)href, LASSO_ECP_HREF) == 0)
		prefix = "Ecp";
	else if (strcmp((char*)href, LASSO_PAOS_HREF) == 0)
		prefix = "Paos";
	else if (strcmp((char*)href, LASSO_SOAP_ENV_HREF) == 0)
		prefix = "Soap";
	else if (strcmp((char*)href, LASSO_DS_HREF) == 0)
		prefix = "Ds";
#ifdef LASSO_WSF_ENABLED
	else if (strcmp((char*)href, LASSO_SOAP_BINDING_HREF) == 0)
		prefix = "SoapBinding";
	else if (strcmp((char*)href, LASSO_SOAP_BINDING_EXT_HREF) == 0)
		prefix = "SoapBindingExt";
	else if (strcmp((char*)href, LASSO_DISCO_HREF) == 0)
		prefix = "Disco";
	else if (strcmp((char*)href, LASSO_IS_HREF) == 0)
		prefix = "Is";
	else if (strcmp((char*)href, LASSO_SA_HREF) == 0)
		prefix = "Sa";
	else if (strcmp((char*)href, LASSO_WSSE_HREF) == 0)
		prefix = "WsSec1";
	else if (strcmp((char*)href, LASSO_WSSE1_HREF) == 0)
		prefix = "WsSec1";
	else if (strcmp((char*)href, LASSO_IDWSF2_DISCOVERY_HREF) == 0)
		prefix = "IdWsf2Disco";
	else if (strcmp((char*)href, LASSO_IDWSF2_SBF_HREF) == 0)
		prefix = "IdWsf2Sbf";
	else if (strcmp((char*)href, LASSO_IDWSF2_SB2_HREF) == 0)
		prefix = "IdWsf2Sb2";
	else if (strcmp((char*)href, LASSO_IDWSF2_UTIL_HREF) == 0)
		prefix = "IdWsf2Util";
	else if (strcmp((char*)href, LASSO_IDWSF2_SEC_HREF) == 0)
		prefix = "IdWsf2Sec";
	else if (strcmp((char*)href, LASSO_IDWSF2_IMS_HREF) == 0)
		prefix = "IdWsf2Ims";
	else if (strcmp((char*)href, LASSO_IDWSF2_IS_HREF) == 0)
		prefix = "IdWsf2Is";
	else if (strcmp((char*)href, LASSO_IDWSF2_PS_HREF) == 0)
		prefix = "IdWsf2Ps";
	else if (strcmp((char*)href, LASSO_IDWSF2_SUBS_HREF) == 0)
		prefix = "IdWsf2Subs";
	else if (strcmp((char*)href, LASSO_IDWSF2_SUBSREF_HREF) == 0)
		prefix = "IdWsf2SubsRef";
	else if (strcmp((char*)href, LASSO_WSA_HREF) == 0)
		prefix = "WsAddr";
#if 0 /* Desactivate DGME lib special casing */
	else if (strcmp((char*)href, "urn:dgme:msp:ed:2007-01") == 0)
		/* FIXME: new namespaces should be possible to add from another library than lasso */
		prefix = "DgmeMspEd";
#endif
	else if ((tmp = lasso_get_prefix_for_idwsf2_dst_service_href((char*)href))
			!= NULL) {
		/* ID-WSF 2 Profile */
		prefix = "IdWsf2DstRef";
		lasso_release_string(tmp);
	} else if ((tmp = lasso_get_prefix_for_dst_service_href((char*)href))
			!= NULL) {
		/* ID-WSF 1 Profile */
		prefix = "Dst";
		lasso_release_string(tmp);
	}

	if (prefix != NULL && strcmp(prefix, "Dst") == 0 && strcmp((char*)nodename, "Status") == 0)
		prefix = "Utility";
	else if (prefix != NULL && strcmp(prefix, "Disco") == 0 && strcmp((char*)nodename, "Status") == 0)
		prefix = "Utility";
	else if (prefix != NULL && strcmp(prefix, "Sa") == 0 && strcmp((char*)nodename, "Status") == 0)
		prefix = "Utility";
#endif

	return prefix;
}

/*
 * _type_name_from_href_and_nodename:
 * @href: the href part of a QName
 * @nodename: the name part of a QName
 *
 * Return value: a typename string if one if found that exists, NULL otherwise.
 */
static char*
_type_name_from_href_and_nodename(char *href, char *nodename) {
	const char *prefix = prefix_from_href_and_nodename(BAD_CAST (href), BAD_CAST (nodename));
	char *typename = NULL;

	if (!href || !nodename)
		return NULL;

	/* FIXME: hardcoded mappings */
	if (strcmp(nodename, "SvcMD") == 0) {
		typename = g_strdup("LassoIdWsf2DiscoSvcMetadata");
	} else if (prefix != NULL && strcmp(prefix, "IdWsf2DstRef") == 0 && strcmp(nodename, "Status") == 0) {
		typename = g_strdup("LassoIdWsf2UtilStatus");
	} else if (prefix != NULL && strcmp(prefix, "WsSec1") == 0 && strcmp(nodename, "Security") == 0) {
		typename = g_strdup("LassoWsSec1SecurityHeader");
	} else if (prefix != NULL && strcmp(prefix, "Soap") == 0 && strcmp(nodename, "detail") == 0) {
		typename = g_strdup("LassoSoapDetail");
	} else {
		/* first try with registered mappings */
		const char *ctypename = lasso_registry_default_get_mapping(href, nodename, LASSO_LASSO_HREF);
		if (ctypename) {
			typename = g_strdup(ctypename);
		}
		/* finally try the default behaviour */
		if (prefix != NULL && typename == NULL) {
			typename = g_strdup_printf("Lasso%s%s", prefix, nodename);
		}
	}

	/* Does it really exist ? */
	if (typename && g_type_from_name (typename) == 0) {
		lasso_release_string(typename);
	}

	return typename;
}

/**
 * _lasso_node_new_from_xmlNode:
 * @node: an xmlNode
 *
 * Builds a new #LassoNode from an xmlNode.
 *
 * Return value: a new node
 **/
static LassoNode*
_lasso_node_new_from_xmlNode(xmlNode *xmlnode)
{
	char *typename = NULL;
	xmlChar *xsitype = NULL;
	LassoNode *node = NULL;
	gboolean fromXsi = FALSE;

	xsitype = xmlGetNsProp(xmlnode, (xmlChar*)"type", (xmlChar*)LASSO_XSI_HREF);
	if (xsitype) {
		xmlChar *xmlPrefix, *separator;
		xmlNsPtr xsiNs = NULL;
		char *xsiNodeName = NULL;

		/** Honor xsi:type  */
		xmlPrefix = (xmlChar*)xsitype;
		separator = (xmlChar*)strchr((char*)xsitype, ':');
		if (separator != NULL) {
			xmlPrefix = (xmlChar*)g_strndup((char*)xmlPrefix, (size_t)(separator - xmlPrefix));
			xsiNs = xmlSearchNs(NULL, xmlnode, xmlPrefix);
			if (xsiNs != NULL) {
				xsiNodeName = g_strdup((char*)(separator+1));
				if (strcmp((char*)xsiNs->href, LASSO_LASSO_HREF) == 0) {
					typename = g_strdup(xsiNodeName);
				}
			}
			lasso_release(xmlPrefix);
		}
		if (! typename && xsiNs && xsiNodeName) {
			typename = _type_name_from_href_and_nodename ((char*)xsiNs->href, xsiNodeName);
		}
		if (! typename && xsiNs) {
			typename = _type_name_from_href_and_nodename ((char*)xsiNs->href, (char*)xmlnode->name);
		}
		lasso_release_xml_string(xsitype);
		if (xsiNodeName)
			lasso_release_string(xsiNodeName);
		if (typename)
			fromXsi = TRUE;
	}

	if (typename == NULL && xmlnode->ns && xmlnode->ns->href) {
		typename = _type_name_from_href_and_nodename ((char*)xmlnode->ns->href, (char*)xmlnode->name);
	}

	if (typename) {
		node = lasso_node_new_from_xmlNode_with_type(xmlnode, typename);
	}
	if (! node) {
		goto cleanup;
	}
	if (! fromXsi) {
		/* if the typename was not obtained via xsi:type but through mapping of the element
		 * name then keep the element name */
		if (LASSO_NODE_GET_CLASS(node)->node_data &&
				LASSO_NODE_GET_CLASS(node)->node_data->node_name &&
				lasso_strisnotequal((char*)xmlnode->name,
					LASSO_NODE_GET_CLASS(node)->node_data->node_name))
		{
			lasso_node_set_custom_nodename(node, (char*)xmlnode->name);
		}

		if (xmlnode->ns && (LASSO_NODE_GET_CLASS(node)->node_data == NULL ||
					LASSO_NODE_GET_CLASS(node)->node_data->ns == NULL ||
					lasso_xmlstrisnotequal(xmlnode->ns->href,
						LASSO_NODE_GET_CLASS(node)->node_data->ns->href)))
		{
			lasso_node_set_custom_namespace(node, (char*)xmlnode->ns->prefix,
					(char*)xmlnode->ns->href);
		}


	}
cleanup:
	lasso_release(typename);

	return node;
}

/**
 * lasso_node_new_from_xmlNode:
 * @node: an xmlNode
 *
 * Builds a new #LassoNode from an xmlNode.
 *
 * Return value: a new node
 **/
LassoNode*
lasso_node_new_from_xmlNode(xmlNode *xmlnode)
{
	if (xmlnode == NULL || xmlnode->ns == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Unable to build a LassoNode from a xmlNode");
		return NULL;
	}
	return _lasso_node_new_from_xmlNode(xmlnode);
}

static LassoNode*
lasso_node_new_from_xmlNode_with_type(xmlNode *xmlnode, char *typename)
{
	GType gtype;
	LassoNode *node;
	int rc = 0;

	if (typename == NULL)
		return _lasso_node_new_from_xmlNode(xmlnode); /* will auto-detect */

	gtype = g_type_from_name(typename);
	if (gtype == 0)
		return NULL;


	node = g_object_new(gtype, NULL);
	if (lasso_flag_memory_debug == TRUE) {
		fprintf(stderr, "allocation of %s (for xmlNode %p) : %p\n", g_type_name(gtype), xmlnode, node);
	}
	rc = lasso_node_init_from_xml(node, xmlnode);
	if (rc) {
		lasso_node_destroy(node);
		return NULL;
	}

	return node;
}

static gboolean
is_base64(const char *message)
{
	const char *c;

	c = message;
	while (*c != 0 && (isalnum((int)*c) || *c == '+' || *c == '/' || *c == '\n' || *c == '\r')) c++;
	while (*c == '=' || *c == '\n' || *c == '\r') c++; /* trailing = */

	if (*c == 0)
		return TRUE;

	return FALSE;
}


/**
 * lasso_node_init_from_message_with_format:
 * @node: a #LassoNode (or derived class)
 * @message: a Liberty message
 * @constraint: LASSO_MESSAGE_FORMAT_UNKNOWN or the format the message must be in
 * @doc_out: a pointer to store the resulting #xmlDoc structure
 * @node_out: a pointer to store the resulting content #xmlNode
 *
 * Parses @message and initialiazes @node fields with data from it.  Message type may be base64,
 * SOAP, XML or query string, correct type is found automatically if contraint is
 * LASSO_MESSAGE_FORMAT_UNKNOWN or is limited to the value given.
 * If the format is one of LASSO_MESSAGE_FORMAT_XML or LASSO_MESSAGE_FORMAT_XML or
 * LASSO_MESSAGE_FORMAT_BASE64 the resulting #xmlDoc and #xmlNode of the message can be retrieved.
 *
 * Return value: a #LassoMessageFormat value.
 **/
LassoMessageFormat
lasso_node_init_from_message_with_format(LassoNode *node, const char *message, LassoMessageFormat constraint, xmlDoc **doc_out, xmlNode **root_out)
{
	char *msg = NULL;
	gboolean b64 = FALSE;
	LassoMessageFormat rc = LASSO_MESSAGE_FORMAT_ERROR;
	xmlDoc *doc = NULL;
	xmlNode *root = NULL;
	gboolean any = constraint == LASSO_MESSAGE_FORMAT_UNKNOWN;

	msg = (char*)message;

	/* BASE64 case */
	if (any || constraint == LASSO_MESSAGE_FORMAT_BASE64) {
		if (message[0] != 0 && is_base64(message)) {
			int rc = 0;

			msg = g_malloc(strlen(message));
			rc = xmlSecBase64Decode((xmlChar*)message, (xmlChar*)msg, strlen(message));
			if (rc >= 0) {
				b64 = TRUE;
			} else {
				lasso_release(msg);
				msg = (char*)message;
			}
		}
	}

	/* XML case */
	if (any || constraint == LASSO_MESSAGE_FORMAT_XML ||
		constraint == LASSO_MESSAGE_FORMAT_BASE64 ||
		constraint == LASSO_MESSAGE_FORMAT_SOAP) {
		if (strchr(msg, '<')) {
			doc = lasso_xml_parse_memory(msg, strlen(msg));
			if (doc == NULL) {
				rc = LASSO_MESSAGE_FORMAT_UNKNOWN;
				goto cleanup;
			}
			root = xmlDocGetRootElement(doc);

			if (any || constraint == LASSO_MESSAGE_FORMAT_SOAP) {
				gboolean is_soap = FALSE;

				is_soap = lasso_xml_is_soap(root);
				if (is_soap) {
					root = lasso_xml_get_soap_content(root);
				}
				rc = lasso_node_init_from_xml(node, root);
				if (rc != 0) {
					rc = LASSO_MESSAGE_FORMAT_XSCHEMA_ERROR;
					goto cleanup;

				}
				if (is_soap) {
					rc = LASSO_MESSAGE_FORMAT_SOAP;
					goto cleanup;
				}
				if (b64) {
					lasso_release(msg);
					rc = LASSO_MESSAGE_FORMAT_BASE64;
					goto cleanup;
				}
				rc = LASSO_MESSAGE_FORMAT_XML;
				goto cleanup;
			}
		}
	}

	/* HTTP query CASE */
	if (any || constraint == LASSO_MESSAGE_FORMAT_QUERY) {
		if (strchr(msg, '&') || strchr(msg, '=')) {
			/* XXX: detect SAML artifact messages to return a different status code ? */
			if (lasso_node_init_from_query(node, msg) == FALSE) {
				goto cleanup;
			}
			rc = LASSO_MESSAGE_FORMAT_QUERY;
			goto cleanup;
		}
	}

cleanup:
	if (doc_out) {
		*doc_out = doc;
		if (root_out) {
			*root_out = root;
		}
	} else {
		lasso_release_doc(doc);
	}
	return rc;
}

/**
 * lasso_node_init_from_message:
 * @node: a #LassoNode (or derived class)
 * @message: a Liberty message
 *
 * Parses @message and initialiazes @node fields with data from it.  Message
 * type may be base64, SOAP, XML or query string, correct type is found
 * automatically.
 *
 * Return value: a #LassoMessageFormat value.
 **/
LassoMessageFormat
lasso_node_init_from_message(LassoNode *node, const char *message)
{
	return lasso_node_init_from_message_with_format(node, message, LASSO_MESSAGE_FORMAT_UNKNOWN, NULL, NULL);
}

/**
 * lasso_node_class_add_snippets:
 * @klass: object class
 * @snippets: array of XmlSnippet (NULL terminated)
 **/
void
lasso_node_class_add_snippets(LassoNodeClass *klass, struct XmlSnippet *snippets)
{
	klass->node_data->snippets = snippets;
}


/**
 * lasso_node_class_add_query_snippets:
 * @klass: object class
 * @snippets: array of QuerySnippet (NULL terminated)
 **/
void
lasso_node_class_add_query_snippets(LassoNodeClass *klass, struct QuerySnippet *snippets)
{
	klass->node_data->query_snippets = snippets;
}

/**
 * lasso_node_class_set_nodename:
 * @klass: object class
 * @name: name for element node
 **/
void
lasso_node_class_set_nodename(LassoNodeClass *klass, char *name)
{
	if (klass->node_data->node_name)
		lasso_release(klass->node_data->node_name);
	klass->node_data->node_name = g_strdup(name);
}


/**
 * lasso_node_class_set_ns:
 * @klass: object class
 * @href: namespace uri
 * @prefix: namespace prefix
 **/
void
lasso_node_class_set_ns(LassoNodeClass *klass, char *href, char *prefix)
{
	if (klass->node_data->ns)
		xmlFreeNs(klass->node_data->ns);
	klass->node_data->ns = xmlNewNs(NULL, (xmlChar*)href, (xmlChar*)prefix);
}

static void
snippet_dump_any(gchar *key, gchar *value, xmlNode *xmlnode)
{
	if (! key)
		return;
	if (! value)
		return;
	/* element tree syntax for setting namespaces */
	if (key && key[0] == '{') {
		char *end = strchr(key, '}');
		char *ns_uri;
		xmlNs *ns;
		if (! end) {
			message(G_LOG_LEVEL_WARNING, "Invalid attribute name: %s", key);
			return;
		}
		ns_uri = g_strndup(key+1, end-(key+1));
		ns = get_or_define_ns(xmlnode, BAD_CAST ns_uri, NULL);
		xmlSetNsProp(xmlnode, ns, BAD_CAST &end[1], BAD_CAST value);
	} else {
		xmlSetProp(xmlnode, BAD_CAST key, BAD_CAST value);
	}
}

static void
apply_snippet_ns(struct XmlSnippet *snippet, xmlNode *xmlnode)
{
	xmlNs *ns;

	if (! xmlnode)
		return;
	if (snippet->ns_uri) {
		if (! xmlnode->ns || !lasso_strisequal((char*)xmlnode->ns->href, (char*)snippet->ns_uri)) {
			ns = get_or_define_ns(xmlnode, BAD_CAST snippet->ns_uri, BAD_CAST snippet->ns_name);
			xmlSetNs(xmlnode, ns);
		}
		/* If not a any snippet, apply given Name, what about xsi:type ? */
	}
	if (! (snippet->type & SNIPPET_ANY) && ! lasso_strisempty(snippet->name) &&
			lasso_strisnotequal((char*)xmlnode->name, (char*)snippet->name))
		xmlNodeSetName(xmlnode, BAD_CAST snippet->name);
}

static void
lasso_node_build_xmlNode_from_snippets(LassoNode *node, LassoNodeClass *class, xmlNode *xmlnode,
		struct XmlSnippet *snippets, gboolean lasso_dump)
{
	struct XmlSnippet *snippet;
	GType g_type;
	xmlNode *t;
	GList *elem;
	struct XmlSnippet *snippet_any_attribute = NULL;

	g_type = G_TYPE_FROM_CLASS(class);

	snippet = snippets;
	while (snippet && snippet->name) {
		void *value = NULL;
		int int_value = 0;
		gboolean bool_value = FALSE;
		char *str = NULL;
		gboolean optional = snippet->type & SNIPPET_OPTIONAL;
		gboolean optional_neg = snippet->type & SNIPPET_OPTIONAL_NEG;
		gboolean multiple = is_snippet_multiple(snippet);

		if (! snippet->offset && ! (snippet->type & SNIPPET_PRIVATE)) {
			goto advance;
		}
		if (lasso_dump == FALSE && snippet->type & SNIPPET_LASSO_DUMP) {
			goto advance;
		}
		if ((snippet->type & 0xff) == SNIPPET_ATTRIBUTE && (snippet->type & SNIPPET_ANY)) {
			snippet_any_attribute = snippet;
			goto advance;
		}
		/* special treatment for 1-* list of nodes, without we would serialize them twice */
		if (multiple && (snippet->type & SNIPPET_JUMP_ON_MATCH && SNIPPET_JUMP_OFFSET(snippet->type) > 0)) {
			snippet++;
			continue;
		}

		// convert input type to string if needed
		if (snippet->type & SNIPPET_INTEGER) {
			int_value = SNIPPET_STRUCT_MEMBER(int, node, g_type, snippet);
			if (int_value == 0 && optional) {
				goto advance;
			}
			if (int_value == -1 && optional_neg) {
				goto advance;
			}
			str = g_strdup_printf("%i", int_value);
		} else if (snippet->type & SNIPPET_BOOLEAN) {
			bool_value = SNIPPET_STRUCT_MEMBER(gboolean, node, g_type, snippet);
			if (bool_value == FALSE  && optional) {
				goto advance;
			}
			str = bool_value ? "true" : "false";
		} else {
			value = SNIPPET_STRUCT_MEMBER(void *, node, g_type, snippet);
			if (value == NULL) {
				goto advance;
			}
			str = value;
		}

		// output type
		switch (snippet->type & 0xff) {
			case SNIPPET_ATTRIBUTE:
				if (snippet->ns_name) {
					xmlNsPtr ns;

					ns = xmlNewNs(xmlnode, (xmlChar*)snippet->ns_uri, (xmlChar*)snippet->ns_name);
					xmlSetNsProp(xmlnode, ns, (xmlChar*)snippet->name, (xmlChar*)str);
				} else {
					xmlSetProp(xmlnode, (xmlChar*)snippet->name, (xmlChar*)str);
				}
				break;
			case SNIPPET_TEXT_CHILD:
				xmlAddChild(xmlnode, xmlNewText((xmlChar*)str));
				break;
			case SNIPPET_NODE:
				{
					xmlNode *t2;
					t2 = lasso_node_get_xmlNode(LASSO_NODE(value), lasso_dump);
					apply_snippet_ns(snippet, t2);
					xmlAddChild(xmlnode, t2);
				} break;
			case SNIPPET_CONTENT:
				xmlNewTextChild(xmlnode, NULL,
						(xmlChar*)snippet->name, (xmlChar*)str);
				break;
			case SNIPPET_NODE_IN_CHILD:
				t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)snippet->name, NULL);
				xmlAddChild(t, lasso_node_get_xmlNode(
							LASSO_NODE(value), lasso_dump));
				break;
			case SNIPPET_LIST_NODES:
				elem = (GList *)value;
				while (elem) {
					xmlNode *subnode = lasso_node_get_xmlNode(
							LASSO_NODE(elem->data), lasso_dump);
					if (subnode) {
						apply_snippet_ns(snippet, subnode);
						xmlAddChild(xmlnode, subnode);
					}
					elem = g_list_next(elem);
				}
				break;
			case SNIPPET_LIST_CONTENT:
				/* sequence of simple elements (no children,
				 * no attrs, just content) */
				elem = (GList *)value;
				while (elem) {
					xmlNode *subnode;
					subnode = xmlNewTextChild(xmlnode, NULL,
							(xmlChar*)snippet->name,
							(xmlChar*)(elem->data));
					apply_snippet_ns(snippet, subnode);
					elem = g_list_next(elem);
				}
				break;
			case SNIPPET_LIST_XMLNODES:
			case SNIPPET_EXTENSION:
				elem = (GList *)value;
				while (elem) {
					xmlAddChild(xmlnode, xmlCopyNode(elem->data, 1));
					elem = g_list_next(elem);
				}
				break;
			case SNIPPET_XMLNODE:
				xmlAddChild(xmlnode, xmlCopyNode((xmlNode *)value, 1));
				break;
			case SNIPPET_SIGNATURE:
				lasso_node_add_signature_template(node, xmlnode, snippet);
				break;
			case SNIPPET_COLLECT_NAMESPACES:
				break;
			case SNIPPET_UNUSED1:
				g_assert_not_reached();
		}
		if (snippet->type & SNIPPET_INTEGER) {
			lasso_release(str);
		}
	advance:
		if ((snippet->type & SNIPPET_JUMP_ON_MATCH) && SNIPPET_JUMP_OFFSET(snippet->type) > 0 && value) {
			snippet += SNIPPET_JUMP_OFFSET(snippet->type);
		} else if (!value && (snippet->type & SNIPPET_JUMP_ON_MISS) && SNIPPET_JUMP_OFFSET(snippet->type) > 0 && value) {
			snippet += SNIPPET_JUMP_OFFSET(snippet->type);
		} else {
			snippet++;
		}
	}

	if (snippet_any_attribute) {
		GHashTable *value = SNIPPET_STRUCT_MEMBER(GHashTable *, node, g_type,
				snippet_any_attribute);
		if (value) {
			g_hash_table_foreach(value, (GHFunc)snippet_dump_any, xmlnode);
		}
	}
}

static void
lasso_node_add_signature_template(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippet_signature)
{
	LassoNodeClass *klass = NULL;
	LassoNodeClassData *node_data = NULL;
	LassoSignatureContext context;
	char *id = NULL;

	node_data = lasso_legacy_get_signature_node_data(node, &klass);
	if (! node_data)
		return;

	if (node_data->sign_type_offset == 0)
		return;

	context = lasso_node_get_signature(node);
	if (! lasso_validate_signature_context(context))
		if (lasso_legacy_extract_and_copy_signature_parameters(node, node_data))
			context = lasso_node_get_signature(node);

	if (snippet_signature->offset) {
		id = SNIPPET_STRUCT_MEMBER(char *, node, G_TYPE_FROM_CLASS(klass), snippet_signature);
	}

	lasso_xmlnode_add_saml2_signature_template(xmlnode, context, id);
}

static struct XmlSnippet*
find_xml_snippet_by_name(LassoNode *node, char *name, LassoNodeClass **class_p)
{
	LassoNodeClass *class;
	struct XmlSnippet *snippet;

	class = LASSO_NODE_GET_CLASS(node);
	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		for (snippet = class->node_data->snippets;
				snippet && snippet->name && strcmp(snippet->name, name) != 0;
				snippet++) ;
		if (snippet && snippet->name) {
			*class_p = class;
			return snippet;
		}
		class = g_type_class_peek_parent(class);
	}
	*class_p = NULL;
	return NULL;
}

static gboolean
find_path(LassoNode *node, char *path, LassoNode **value_node, LassoNodeClass **class_p, struct XmlSnippet **snippet)
{
	char *s, *t;
	struct XmlSnippet *tsnippet = NULL;
	LassoNode *tnode = node;

	*class_p = NULL;
	s = path;
	while (s) {
		t = strchr(s, '/');
		if (t) *t = 0;
		tsnippet = find_xml_snippet_by_name(tnode, s, class_p);
		if (t) {
			tnode = SNIPPET_STRUCT_MEMBER(LassoNode *, tnode, G_TYPE_FROM_CLASS(*class_p),
					tsnippet);
			if (tnode == NULL)
				return FALSE;

			s = t+1;
		} else {
			s = NULL;
		}
	}

	if (tsnippet == NULL)
		return FALSE;

	*snippet = tsnippet;
	*value_node = tnode;
	return TRUE;
}


static char*
get_value_by_path(LassoNode *node, char *path, struct XmlSnippet *xml_snippet)
{
	struct XmlSnippet *snippet;
	LassoNode *value_node;
	LassoNodeClass *class;
	GType g_type;

	if (find_path(node, path, &value_node, &class, &snippet) != TRUE)
		return NULL;
	g_type = G_TYPE_FROM_CLASS(class);

	*xml_snippet = *snippet;

	if (snippet->type & SNIPPET_BOOLEAN) {
		gboolean v = SNIPPET_STRUCT_MEMBER(gboolean, value_node, g_type, snippet);
		return v ? g_strdup("true") : g_strdup("false");
	} else if (snippet->type & SNIPPET_INTEGER) {
		int v = SNIPPET_STRUCT_MEMBER(int, value_node, g_type, snippet);
		return g_strdup_printf("%d", v);
	} else if (snippet->type == SNIPPET_NODE) {
		LassoNode *value = SNIPPET_STRUCT_MEMBER(LassoNode *, value_node, g_type, snippet);
		return lasso_node_build_query(value);
	} else if (snippet->type == SNIPPET_EXTENSION) {
		/* convert all of the <lib:Extension> into a string, already
		 * escaped for URI usage */
		GList *value = SNIPPET_STRUCT_MEMBER(GList *, value_node, g_type, snippet);
		xmlChar *s, *s2;
		GString *result = g_string_new("");
		while (value) {
			xmlNode *t = value->data;
			xmlNode *c;

			/* attributes */
#if 0
			xmlAttr *a;
			for (a = t->properties; a; a = a->next) {
				if (result->len)
					g_string_append(result, "&");
				s = xmlGetProp(t, a->name);
				g_string_append(result, a->name);
				g_string_append(result, "=");
				s2 = xmlURIEscapeStr(s, NULL);
				g_string_append(result, s2);
				xmlFree(s2);
				xmlFree(s);
			}
#endif

			/* children (only simple ones and 1-level deep) */
			for (c = t->children; c; c = c->next) {
				if (c->type != XML_ELEMENT_NODE)
					continue;
				if (c->children->type != XML_TEXT_NODE)
					continue;
				if (c->properties != NULL)
					continue;
				if (result->len)
					g_string_append(result, "&");
				g_string_append(result, (char*)c->name);
				g_string_append(result, "=");
				s = xmlNodeGetContent(c);
				s2 = xmlURIEscapeStr(s, NULL);
				g_string_append(result, (char*)s2);
				xmlFree(s2);
				xmlFree(s);
			}

			value = g_list_next(value);
		}
		if (result->len == 0) {
			lasso_release_gstring(result, TRUE);
			return NULL;
		}
		return g_string_free(result, FALSE);
	} else if (snippet->type == SNIPPET_LIST_CONTENT) {
		/* not clear in spec; concat values with spaces */
		GList *value = SNIPPET_STRUCT_MEMBER(GList *, value_node, g_type, snippet);
		GString *result = g_string_new("");
		while (value) {
			result = g_string_append(result, (char*)value->data);
			if (value->next)
				result = g_string_append(result, " ");
			value = value->next;
		}
		if (result->len == 0) {
			lasso_release_gstring(result, TRUE);
			return NULL;
		}
		return g_string_free(result, FALSE);
	} else {
		char *value = SNIPPET_STRUCT_MEMBER(char *, value_node, g_type, snippet);
		if (value == NULL) return NULL;
		return g_strdup(value);
	}
	return NULL;
}

static gboolean
set_value_at_path(LassoNode *node, char *path, char *query_value)
{
	struct XmlSnippet *snippet;
	LassoNode *value_node;
	LassoNodeClass *class;
	GType g_type;
	void *value;

	if (find_path(node, path, &value_node, &class, &snippet) != TRUE)
		return FALSE;
	g_type = G_TYPE_FROM_CLASS(class);

	value = SNIPPET_STRUCT_MEMBER_P(value_node, g_type, snippet);

	if (snippet->type & SNIPPET_INTEGER) {
		int val = atoi(query_value);
		(*(int*)value) = val;
	} else if (snippet->type & SNIPPET_BOOLEAN) {
		int val = (strcmp(query_value, "true") == 0);
		(*(int*)value) = val;
	} else if (snippet->type == SNIPPET_NODE) {
		LassoNode *v = *(LassoNode**)value;
		if (v == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "building node from query; unknown subnode");
			g_assert_not_reached();
		}
		LASSO_NODE_GET_CLASS(v)->init_from_query(v, &query_value);
	} else if (snippet->type == SNIPPET_LIST_CONTENT) {
		char **elems = g_strsplit(query_value, " ", 0);
		int i;
		GList *l = NULL;
		for (i = 0; elems[i]; i++) {
			l = g_list_append(l, g_strdup(elems[i]));
		}
		g_strfreev(elems);
		(*(GList**)value) = l;
	} else {
		(*(char**)value) = g_strdup(query_value);
	}

	return TRUE;
}


gchar*
lasso_node_build_query_from_snippets(LassoNode *node)
{
	int i;
	char path[100];
	char *v;
	GString *s;
	xmlChar *t;
	LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
	struct QuerySnippet *query_snippets = NULL;
	struct XmlSnippet xml_snippet;

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		if (class->node_data && class->node_data->query_snippets) {
			query_snippets = class->node_data->query_snippets;
			break;
		}
		class = g_type_class_peek_parent(class);
	}
	if (query_snippets == NULL)
		return NULL;

	s = g_string_sized_new(2000);

	for (i=0; query_snippets[i].path; i++) {
		g_strlcpy(path, query_snippets[i].path, 100);
		v = get_value_by_path(node, path, &xml_snippet);
		if (v && xml_snippet.type == SNIPPET_EXTENSION) {
			if (s->len)
				g_string_append(s, "&");
			g_string_append(s, v);
			lasso_release(v);
			continue;
		}
		if (v) {
			char *field_name = query_snippets[i].field_name;
			if (field_name == NULL)
				field_name = query_snippets[i].path;
			if (s->len)
				g_string_append(s, "&");
			g_string_append(s, field_name);
			g_string_append(s, "=");
			t = xmlURIEscapeStr((xmlChar*)v, NULL);
			g_string_append(s, (char*)t);
			xmlFree(t);
		}
		if (v)
			lasso_release(v);
	}

	return g_string_free(s, FALSE);
}


gboolean
lasso_node_init_from_query_fields(LassoNode *node, char **query_fields)
{
	int i, j;
	char *field, *t;
	LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
	struct QuerySnippet *query_snippets = NULL;
	gboolean has_extension = FALSE;

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		if (class->node_data && class->node_data->query_snippets) {
			query_snippets = class->node_data->query_snippets;
			break;
		}
		class = g_type_class_peek_parent(class);
	}
	if (query_snippets == NULL)
		return FALSE;

	for (i = 0; (field = query_fields[i]); i++) {
		t = strchr(field, '=');
		if (t == NULL)
			continue;
		*t = 0;

		for (j=0; query_snippets[j].path; j++) {
			char *field_name = query_snippets[j].field_name;
			char path[100];

			g_strlcpy(path, query_snippets[j].path, 100);

			if (field_name == NULL)
				field_name = query_snippets[j].path;
			if (strcmp(field_name, "Extension") == 0) {
				has_extension = TRUE;
				continue;
			}
			if (strcmp(field, field_name) != 0)
				continue;
			set_value_at_path(node, path, t+1);
			break;
		}
		if (query_snippets[j].path == NULL && has_extension &&
				strcmp(field, "SigAlg") != 0 && strcmp(field, "Signature") != 0) {
			/* got to the end without finding anything; and has
			 * Extension; build it */
			struct XmlSnippet *extension_snippet;
			LassoNode *value_node;
			LassoNodeClass *class;
			GList **value;
			xmlNode *xmlnode, *xmlchild;
			if (find_path(node, "Extension", &value_node, &class, &extension_snippet) == TRUE) {
				GType g_type = G_TYPE_FROM_CLASS(class);
				value = SNIPPET_STRUCT_MEMBER_P(value_node, g_type,
						extension_snippet);
				if (*value) {
					xmlnode = (*value)->data;
				} else {
					xmlnode = xmlNewNode(xmlNewNs(NULL,
								(xmlChar*)LASSO_LIB_HREF,
								(xmlChar*)LASSO_LIB_PREFIX),
							(xmlChar*)"Extension");
				}
				xmlchild = xmlNewNode(NULL, (xmlChar*)field);
				xmlAddChild(xmlchild, xmlNewText((xmlChar*)t+1));
				xmlAddChild(xmlnode, xmlchild);
				if (! *value)
					*value = g_list_append(*value, xmlnode);
			}
		}
		*t = '=';
	}

	return TRUE;
}

gboolean
lasso_node_init_from_saml2_query_fields(LassoNode *node, char **query_fields, G_GNUC_UNUSED char **relay_state)
{
	int i;
	char *field, *t;
	char *req = NULL;
	char *enc = NULL;
	gboolean rc;

	for (i=0; (field=query_fields[i]); i++) {
		t = strchr(field, '=');
		if (t == NULL)
			continue;
		*t = 0;
		if (strcmp(field, LASSO_SAML2_FIELD_ENCODING) == 0) {
			enc = t+1;
			continue;
		}
		if (strcmp(field, LASSO_SAML2_FIELD_REQUEST) == 0 || strcmp(field, LASSO_SAML2_FIELD_RESPONSE) == 0) {
			req = t+1;
			continue;
		}
	}

	if (enc && strcmp(enc, LASSO_SAML2_DEFLATE_ENCODING) != 0) {
		/* unknown encoding */
		message(G_LOG_LEVEL_CRITICAL, "Unknown URL encoding: %s", enc);
		return FALSE;
	}

	if (req == NULL) {
		return FALSE;
	}

	rc = lasso_node_init_from_deflated_query_part(node, req);
	if (rc == FALSE) {
		return rc;
	}

	return TRUE;
}

static void
xmlDeclareNs(xmlNode *root_node, xmlNode *node)
{
	xmlNs *ns;
	xmlNode *t;

	if (strcmp((char*)node->name, "Signature") == 0)
		return;

	for (ns = node->nsDef; ns; ns = ns->next) {
		if (ns->prefix && strcmp((char*)ns->prefix, "xsi") != 0) {
			xmlNewNs(root_node, ns->href, ns->prefix);
		}
	}
	for (t = node->children; t; t = t->next) {
		if (t->type == XML_ELEMENT_NODE) {
			xmlDeclareNs(root_node, t);
		}
	}
}

static inline int
sameNs(xmlNs *ns1, xmlNs *ns2)
{
	/* this checks ns->prefix instead of ns->href so it is possible to
	 * merge down to an earlier version of liberty namespace
	 */
	return (ns1 == NULL && ns2 == NULL) || (
			ns1 && ns2 && ns1->prefix && ns2->prefix &&
			strcmp((char*)ns1->prefix, (char*)ns2->prefix) == 0 &&
			strcmp((char*)ns1->href, (char*)ns2->href) == 0);
}

static void
xmlPropUseNsDef(xmlNs *ns, xmlNode *node)
{
	xmlAttr *attr;

	for (attr = node->properties; attr; attr = attr->next) {
		if (sameNs(ns, attr->ns)) {
			attr->ns = ns;
		}
	}
}

static void
xmlUseNsDef(xmlNs *ns, xmlNode *node)
{
	xmlNode *t;
	xmlNs *ns2;
	xmlNs *ns3 = NULL;

	xmlPropUseNsDef(ns, node);
	if (sameNs(ns, node->ns)) {
		node->ns = ns;
	}

	for (t = node->children; t; t = t->next) {
		if (t->type == XML_ELEMENT_NODE)
			xmlUseNsDef(ns, t);
	}

	if (sameNs(node->nsDef, ns)) {
		ns3 = node->nsDef;
		node->nsDef = node->nsDef->next;
		xmlFreeNs(ns3);
	} else if (node->nsDef) {
		for (ns2 = node->nsDef; ns2->next; ns2 = ns2->next) {
			if (sameNs(ns2->next, ns)) {
				ns3 = ns2->next;
				ns2->next = ns2->next->next;
				xmlFreeNs(ns3);
				if (ns2->next == NULL)
					break;
			}
		}
	}
}

/**
 * xmlCleanNs
 * @root_node: the root #xmlNode where to start the cleaning.
 *
 * xmlCleanNs removes duplicate xml namespace declarations and merge them on
 * the @root_node.
 **/
void
xmlCleanNs(xmlNode *root_node)
{
	xmlNs *ns;
	xmlNode *t;

	for (t = root_node->children; t; t = t->next)
		if (t->type == XML_ELEMENT_NODE)
			xmlDeclareNs(root_node, t);

	for (ns = root_node->nsDef; ns; ns = ns->next) {
		for (t = root_node->children; t; t = t->next)
			if (t->type == XML_ELEMENT_NODE)
				xmlUseNsDef(ns, t);
	}
}

void
xml_insure_namespace(xmlNode *xmlnode, xmlNs *ns, gboolean force, gchar *ns_href, gchar *ns_prefix)
{
	xmlNode *t = xmlnode->children;

	if (ns == NULL) {
		for (ns = xmlnode->nsDef; ns; ns = ns->next) {
			if (ns->href && lasso_strisequal((gchar *)ns->href,ns_href)) {
				break;
			}
		}
		if (ns == NULL) {
			ns = xmlNewNs(xmlnode, (xmlChar*)ns_href, (xmlChar*)ns_prefix);
		}
	}

	xmlSetNs(xmlnode, ns);
	while (t) {
		if (t->type == XML_ELEMENT_NODE && (force == TRUE || t->ns == NULL)) {
			xml_insure_namespace(t, ns, force, NULL, NULL);
		}
		t = t->next;
	}
}

/**
 * lasso_node_get_xmlnode_for_any_type:
 * @node: a #LassoNode.
 * @xmlnode: the #xmlNode returned.
 *
 * Return value: a xmlNode completed with the content of the produced by the get_xmlNode virtual
 * method of the parent class.
 */
xmlNode*
lasso_node_get_xmlnode_for_any_type(LassoNode *node, xmlNode *cur)
{
	xmlNode *original_xmlnode;

	original_xmlnode = lasso_node_get_original_xmlnode(node);
	if (cur) {
		if (original_xmlnode) {
			xmlNode *children = xmlCopyNodeList(original_xmlnode->children);
			xmlAttr *attrs = xmlCopyPropList(cur, original_xmlnode->properties);
			if (cur->properties == NULL) {
				cur->properties = attrs;
			} else {
				xmlAttr *it = cur->properties;
				while (it->next) {
					it = it->next;
				}
				it->next = attrs;
			}
			xmlAddChildList(cur, children);
			return cur;
		} else {
			return cur;
		}
	} else {
		if (original_xmlnode) {
			return xmlCopyNode(original_xmlnode, 1);
		} else {
			return cur;
		}
	}
}

/**
 * lasso_node_get_name:
 * @node: a #LassoNode
 *
 * Return the XML element name for this object, the one that would be used in the XML dump of this
 * object.
 *
 * Return value: the name of the object, the value must not be stored.
 */
const char*
lasso_node_get_name(LassoNode *node)
{
	struct _CustomElement *custom_element;
	LassoNodeClass *klass;
	g_return_val_if_fail(LASSO_IS_NODE(node), NULL);

	custom_element = _lasso_node_get_custom_element(node);
	if (custom_element && custom_element->nodename) {
		return custom_element->nodename;
	}
	klass = LASSO_NODE_GET_CLASS(node);
	return klass->node_data->node_name;
}

/**
 * lasso_node_get_name:
 * @node: a #LassoNode
 *
 * Return the XML element name for this object, the one that would be used in the XML dump of this
 * object.
 *
 * Return value: the name of the object, the value must not be stored.
 */
const char*
lasso_node_get_namespace(LassoNode *node)
{
	struct _CustomElement *custom_element;
	LassoNodeClass *klass;
	g_return_val_if_fail(LASSO_IS_NODE(node), NULL);

	custom_element = _lasso_node_get_custom_element(node);
	if (custom_element && custom_element->nodename) {
		return custom_element->href;
	}
	klass = LASSO_NODE_GET_CLASS(node);
	if (klass->node_data && klass->node_data->ns)
		return (const char*)klass->node_data->ns->href;
	return NULL;
}


/**
 * lasso_node_export_to_saml2_query:
 * @node: the #LassoNode object to pass as a query
 * @param_name: the key value for the query string parameter
 * @url:(allow-none): an optional URL to prepend to the query string
 * @key:(allow-none): a #LassoKey object
 *
 * Export a node as signed query string, the node must support serialization as a query.
 *
 * Return value: an HTTP URL or query string if successful, NULL otherwise.
 */
char*
lasso_node_export_to_saml2_query(LassoNode *node, const char *param_name, const char *url,
		LassoKey *key)
{
	char *value = NULL, *query = NULL, *signed_query = NULL, *result = NULL;
	xmlChar *encoded_param = NULL;

	value = lasso_node_build_deflated_query(node);
	if (! value)
		goto cleanup;
	encoded_param = xmlURIEscapeStr(BAD_CAST param_name, NULL);
	if (! encoded_param)
		goto cleanup;
	query = g_strdup_printf("%s=%s", encoded_param, value);
	if (! query)
		goto cleanup;
	if (LASSO_IS_KEY(key)) {
		signed_query = lasso_key_query_sign(key, query);
	} else {
		lasso_transfer_string(signed_query, query);
	}
	if (! signed_query)
		goto cleanup;
	if (url) {
		result = lasso_concat_url_query(url, signed_query);
	} else {
		lasso_transfer_string(result, signed_query);
	}

cleanup:
	lasso_release_string(value);
	lasso_release_xml_string(encoded_param);
	lasso_release_string(query);
	lasso_release_string(signed_query);
	return result;
}

/**
 * lasso_node_new_from_saml2_query:
 * @url_or_qs: an URL containing a query string or a query string only
 * @param_name: the key value for the query string parameter to extract as a #LassoNode.
 * @key:(allow-none): a #LassoKey object
 *
 * Verify the signature on a SAML-2 encoded query string and return the encoded node.
 *
 * Return value: a newly build #LassoNode if successful, NULL otherwise.
 */
LassoNode*
lasso_node_new_from_saml2_query(const char *url_or_qs, const char *param_name, LassoKey *key)
{
	char *needle = NULL;
	LassoNode *result = NULL;

	if (! url_or_qs || ! param_name)
		return NULL;
	needle = strchr(url_or_qs, '?');
	if (needle) {
		url_or_qs = (const char*)(needle+1);
	}
	if (key) {
		goto_cleanup_if_fail(lasso_key_query_verify(key, url_or_qs) == 0);
	}
cleanup:
	return result;
}
