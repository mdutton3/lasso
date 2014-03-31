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

#ifndef __LASSO_XML_PRIVATE_H__
#define __LASSO_XML_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "xml_enc.h"
#include <xmlsec/crypto.h>
#include <xmlsec/xmlenc.h>
#include "saml-2.0/saml2_encrypted_element.h"
#include "../utils.h"

typedef enum {
	SNIPPET_NODE,
	SNIPPET_CONTENT,
	SNIPPET_TEXT_CHILD,
	SNIPPET_UNUSED1,
	SNIPPET_ATTRIBUTE,
	SNIPPET_NODE_IN_CHILD,
	SNIPPET_LIST_NODES,
	SNIPPET_LIST_CONTENT,
	SNIPPET_EXTENSION,
	SNIPPET_SIGNATURE,
	SNIPPET_LIST_XMLNODES,
	SNIPPET_XMLNODE,
	SNIPPET_COLLECT_NAMESPACES,
	SNIPPET_JUMP_OFFSET_SIGN = 1 << 19,
	SNIPPET_JUMP_OFFSET_SHIFT = 15,
	SNIPPET_JUMP_OFFSET_MASK = 0x0f << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_1 = 1 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_2 = 2 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_3 = 3 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_4 = 4 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_5 = 5 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_6 = 6 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_JUMP_7 = 7 << SNIPPET_JUMP_OFFSET_SHIFT,
	SNIPPET_BACK_1 = 1 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	SNIPPET_BACK_2 = 2 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	SNIPPET_BACK_3 = 3 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	SNIPPET_BACK_4 = 4 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	SNIPPET_BACK_5 = 5 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	SNIPPET_BACK_6 = 6 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	SNIPPET_BACK_7 = 7 << SNIPPET_JUMP_OFFSET_SHIFT | SNIPPET_JUMP_OFFSET_SIGN,
	/* transformers for content transformation */
	SNIPPET_STRING  = 1 << 0, /* default, can be omitted */
	SNIPPET_BOOLEAN = 1 << 20,
	SNIPPET_INTEGER = 1 << 21,
	SNIPPET_LASSO_DUMP = 1 << 22,
	SNIPPET_OPTIONAL = 1 << 23, /* optional, ignored if 0 */
	SNIPPET_OPTIONAL_NEG = 1 << 24, /* optional, ignored if -1 */
	SNIPPET_ANY = 1 << 25, /* ##any node */
	SNIPPET_ALLOW_TEXT = 1 << 26, /* allow text childs in list of nodes */
	SNIPPET_KEEP_XMLNODE = 1 << 27, /* force keep xmlNode */
	SNIPPET_PRIVATE = 1 << 28, /* means that the offset is relative to a private extension */
	SNIPPET_MANDATORY = 1 << 29, /* means that the element cardinality is at least 1 */
	SNIPPET_JUMP_ON_MATCH = 1 << 30,
	SNIPPET_JUMP_ON_MISS = 1 << 31,
	SNIPPET_JUMP = SNIPPET_JUMP_ON_MISS | SNIPPET_JUMP_ON_MATCH,

} SnippetType;

#define SNIPPET_JUMP_OFFSET(type) ((type & SNIPPET_JUMP_OFFSET_SIGN) ? \
		                      (-(type & SNIPPET_JUMP_OFFSET_MASK) >> SNIPPET_JUMP_OFFSET_SHIFT) \
		                    : ((type & SNIPPET_JUMP_OFFSET_MASK) >> SNIPPET_JUMP_OFFSET_SHIFT))

typedef enum {
	NO_OPTION = 0,
	NO_SINGLE_REFERENCE = 1 /* SAML signature should contain a single reference,
				  * but WS-Security signatures can contain many */,
	EMPTY_URI = 2,
} SignatureVerificationOption;

struct XmlSnippet {
	char *name; /* name of the node or attribute to match */
	SnippetType type; /* type of node to deserialize */
	guint offset; /* offset of the storage field relative to the public or private object (if
			 using SNIPPET_PRIVATE). If 0, means that no storage must be done, it will
			 be handled by the init_from_xml virtual method. */
	char *class_name; /* Force a certain LassoNode class for deserializing a node, usually
			     useless. */
	char *ns_name; /* if the namespace is different from the one of the parent node, specify it
			  there */
	char *ns_uri;
};

/**
 * LassoSignatureContext:
 * @signature_method: the method for signing (RSA, DSA, HMAC)
 * @signature_key: a key for the signature
 *
 * Information needed to make a signature
 */
typedef struct _LassoSignatureContext {
	LassoSignatureMethod signature_method;
	xmlSecKey *signature_key;
} LassoSignatureContext;

#define LASSO_SIGNATURE_CONTEXT_NONE ((LassoSignatureContext){LASSO_SIGNATURE_TYPE_NONE, NULL})

#define lasso_assign_signature_context(to, from) \
	do { \
		LassoSignatureContext *__to = &(to); \
		LassoSignatureContext __from = (from); \
		__to->signature_method = __from.signature_method; \
		lasso_assign_sec_key(__to->signature_key, __from.signature_key); \
	} while(0)

#define lasso_assign_new_signature_context(to, from) \
	do { \
		LassoSignatureContext *__to = &(to); \
		LassoSignatureContext __from = (from); \
		__to->signature_method = __from.signature_method; \
		lasso_assign_new_sec_key(__to->signature_key, __from.signature_key); \
	} while(0)

static inline gboolean
lasso_validate_signature_context(LassoSignatureContext context) {
	return lasso_validate_signature_method(context.signature_method)
		&& context.signature_key != NULL;
}

/**
 * This inline method replace normal use of G_STRUCT_MEMBER_P/G_STRUCT_MEMBER, in order to add an
 * indirection through the private structure attached to a GObject instance if needed */
inline static void *
snippet_struct_member(void *base, GType type, struct XmlSnippet *snippet)
{
	if (snippet->type & SNIPPET_PRIVATE) {
		if (! G_IS_OBJECT(base))
			return NULL;
		GObject *object = (GObject*)base;
		base = g_type_instance_get_private((GTypeInstance*)object,
				type);
	}
	return G_STRUCT_MEMBER_P(base, snippet->offset);
}

#define SNIPPET_STRUCT_MEMBER(type, base, gtype, snippet) \
	(*(type*)snippet_struct_member(base, gtype, snippet))

#define SNIPPET_STRUCT_MEMBER_P(base, gtype, snippet) \
	snippet_struct_member(base, gtype, snippet)

struct QuerySnippet {
	char *path;
	char *field_name;
};

struct _LassoNodeClassData
{
	struct XmlSnippet *snippets;
	struct QuerySnippet *query_snippets;
	char *node_name;
	xmlNs *ns;
	char *id_attribute_name;
	int id_attribute_offset;
	int sign_type_offset;
	int sign_method_offset;
	int private_key_file_offset;
	int certificate_file_offset;
	gboolean keep_xmlnode;
	gboolean xsi_sub_type;
};

void lasso_node_class_set_nodename(LassoNodeClass *klass, char *name);
void lasso_node_class_set_ns(LassoNodeClass *klass, char *href, char *prefix);
void lasso_node_class_add_snippets(LassoNodeClass *klass, struct XmlSnippet *snippets);
void lasso_node_class_add_query_snippets(LassoNodeClass *klass, struct QuerySnippet *snippets);

gchar* lasso_node_build_query_from_snippets(LassoNode *node);
gboolean lasso_node_init_from_query_fields(LassoNode *node, char **query_fields);
gboolean lasso_node_init_from_saml2_query_fields(LassoNode *node,
		char **query_fields, char **relay_state);
LassoMessageFormat lasso_node_init_from_message_with_format(LassoNode *node, const char *message, LassoMessageFormat constraint, xmlDoc **doc_out, xmlNode **root_out);

typedef enum {
	LASSO_PEM_FILE_TYPE_UNKNOWN,
	LASSO_PEM_FILE_TYPE_PUB_KEY,
	LASSO_PEM_FILE_TYPE_PRIVATE_KEY,
	LASSO_PEM_FILE_TYPE_CERT
} LassoPemFileType;

void  lasso_build_random_sequence(char *buffer, unsigned int size);
char* lasso_build_unique_id(unsigned int size);
char* lasso_get_current_time(void);
char* lasso_time_to_iso_8601_gmt(time_t now);
time_t lasso_iso_8601_gmt_to_time_t(const char *xsdtime);
LassoPemFileType lasso_get_pem_file_type(const char *file);

xmlSecKeyPtr lasso_get_public_key_from_pem_file(const char *file);
xmlSecKeyPtr lasso_get_public_key_from_pem_cert_file(const char *file);
xmlSecKeysMngr* lasso_load_certs_from_pem_certs_chain_file (const char *file);

char* lasso_query_sign(char *query, LassoSignatureContext signature_context);

int lasso_query_verify_signature(const char *query, const xmlSecKey *public_key);

int lasso_saml2_query_verify_signature(const char *query, const xmlSecKey *sender_public_key);

char* lasso_sha1(const char *str);

char* lasso_sha256(const char *str);

char* lasso_sha384(const char *str);

char* lasso_sha512(const char *str);

char** urlencoded_to_strings(const char *str);

int lasso_sign_node(xmlNode *xmlnode, LassoSignatureContext context, const char *id_attr_name, const char *id_value);

int lasso_verify_signature(xmlNode *signed_node, xmlDoc *doc, const char *id_attr_name,
		xmlSecKeysMngr *keys_manager, xmlSecKey *public_key,
		SignatureVerificationOption signature_verification_option,
		GList **uri_references);
void xmlCleanNs(xmlNode *root_node);

void xml_insure_namespace(xmlNode *xmlnode, xmlNs *ns, gboolean force,
		gchar *ns_href, gchar *ns_prefix);

gchar* lasso_node_build_deflated_query(LassoNode *node);

gchar* lasso_node_build_query(LassoNode *node);

gboolean lasso_node_init_from_deflated_query_part(LassoNode *node, char *deflate_string);

xmlNode* lasso_node_get_xmlnode_for_any_type(LassoNode *node, xmlNode *cur);

LassoSaml2EncryptedElement* lasso_node_encrypt(LassoNode *lasso_node,
	xmlSecKey *encryption_public_key, LassoEncryptionSymKeyType encryption_sym_key_type, const char *recipient);

int lasso_node_decrypt_xmlnode(xmlNode* encrypted_element, GList *encrypted_key,
		xmlSecKey *encryption_private_key, LassoNode **output);

void lasso_node_remove_signature(LassoNode *node);

char* lasso_concat_url_query(const char *url, const char *query);

xmlDocPtr lasso_xml_parse_memory(const char *buffer, int size);

xmlNode* lasso_xml_get_soap_content(xmlNode *root);

gboolean lasso_xml_is_soap(xmlNode *root);

gboolean lasso_eval_xpath_expression(xmlXPathContextPtr xpath_ctx, const char *expression,
		xmlXPathObjectPtr *xpath_object_ptr, int *xpath_error_code);

#define IF_SAML2(profile) \
	if (lasso_provider_get_protocol_conformance(LASSO_PROVIDER(profile->server)) == \
			LASSO_PROTOCOL_SAML_2_0)

char * lasso_get_relaystate_from_query(const char *query);
char * lasso_url_add_parameters(char *url, gboolean free, ...);
xmlSecKey* lasso_xmlsec_load_private_key_from_buffer(const char *buffer, size_t length, const char *password, LassoSignatureMethod signature_method, const char *certificate);
xmlSecKey* lasso_xmlsec_load_private_key(const char *filename_or_buffer, const char *password,
		LassoSignatureMethod signature_method, const char *certificate);
xmlDocPtr lasso_xml_parse_file(const char *filepath);
xmlDocPtr lasso_xml_parse_memory_with_error(const char *buffer, int size, xmlError *error);
xmlSecKeyPtr lasso_xmlsec_load_key_info(xmlNode *key_descriptor);
char* lasso_xmlnode_to_string(xmlNode *node, gboolean format, int level);
gboolean lasso_string_to_xsd_integer(const char *str, long int *integer);
void lasso_set_string_from_prop(char **str, xmlNode *node, xmlChar *name, xmlChar *ns);

void lasso_node_add_custom_namespace(LassoNode *node, const char *prefix, const char *href);

int lasso_node_set_signature(LassoNode *node, LassoSignatureContext context);

LassoSignatureContext lasso_node_get_signature(LassoNode *node);

void lasso_node_set_encryption(LassoNode *node, xmlSecKey *encryption_public_key,
		LassoEncryptionSymKeyType encryption_sym_key_type);

void lasso_node_get_encryption(LassoNode *node, xmlSecKey **encryption_public_key,
		LassoEncryptionSymKeyType *encryption_sym_key_type);
gboolean lasso_base64_decode(const char *from, char **buffer, int *buffer_len);

xmlSecKeyPtr
lasso_create_hmac_key(const xmlSecByte * buf, xmlSecSize size);

lasso_error_t
lasso_get_hmac_key(const xmlSecKey *key, void **buffer, size_t *size);

LassoSignatureContext lasso_make_signature_context_from_buffer(const void *buffer, size_t length,
		const char *password, LassoSignatureMethod signature_method,
		const char *certificate);

LassoSignatureContext lasso_make_signature_context_from_path_or_string(char *filename_or_buffer,
		const char *password, LassoSignatureMethod signature_method,
		const char *certificate);

xmlNs * get_or_define_ns(xmlNode *xmlnode, const xmlChar *ns_uri, const xmlChar
		*advised_prefix);

void set_qname_attribute(xmlNode *node,
		const xmlChar *attribute_ns_prefix,
		const xmlChar *attribute_ns_href,
		const xmlChar *attribute_name,
		const xmlChar *prefix,
		const xmlChar *href,
		const xmlChar *name);


void set_xsi_type(xmlNode *node,
		const xmlChar *type_ns_prefix,
		const xmlChar *type_ns_href,
		const xmlChar *type_name);

void lasso_xmlnode_add_saml2_signature_template(xmlNode *node, LassoSignatureContext context,
		const char *id);

gchar* lasso_xmlnode_build_deflated_query(xmlNode *xmlnode);

xmlTextReader *lasso_xmltextreader_from_message(const char *message, xmlChar **to_free);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_PRIVATE_H__ */
