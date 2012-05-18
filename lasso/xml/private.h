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

#ifndef __LASSO_TOOLS_H__
#define __LASSO_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/xml/xml.h>
#include <lasso/xml/xml_enc.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmlenc.h>
#include <lasso/xml/saml-2.0/saml2_encrypted_element.h>

typedef enum {
	SNIPPET_NODE,
	SNIPPET_CONTENT,
	SNIPPET_TEXT_CHILD,
	SNIPPET_NAME_IDENTIFIER,
	SNIPPET_ATTRIBUTE,
	SNIPPET_NODE_IN_CHILD,
	SNIPPET_LIST_NODES,
	SNIPPET_LIST_CONTENT,
	SNIPPET_EXTENSION,
	SNIPPET_SIGNATURE,
	SNIPPET_LIST_XMLNODES,
	SNIPPET_XMLNODE,

	/* transformers for content transformation */
	SNIPPET_STRING  = 1 << 0, /* default, can be omitted */
	SNIPPET_BOOLEAN = 1 << 20,
	SNIPPET_INTEGER = 1 << 21,
	SNIPPET_LASSO_DUMP = 1 << 22,
	SNIPPET_OPTIONAL = 1 << 23, /* optional, ignored if 0 */
	SNIPPET_OPTIONAL_NEG = 1 << 24, /* optional, ignored if -1 */
	SNIPPET_ANY = 1 << 25, /* ##any node */
	SNIPPET_ALLOW_TEXT = 1 << 26, /* allow text childs in list of nodes */
	SNIPPET_KEEP_XMLNODE = 1 << 27 /* force keep xmlNode */
} SnippetType;

typedef enum {
	NO_OPTION = 0,
	NO_SINGLE_REFERENCE = 1 /* SAML signature should contain a single reference,
				  * but WS-Security signatures can contain many */
} SignatureVerificationOption;

struct XmlSnippet {
	char *name;
	SnippetType type;
	guint offset;
	char *class_name;
	char *ns_name;
	char *ns_uri;
};

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
	int sign_type_offset;
	int sign_method_offset;
	gboolean keep_xmlnode;
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
LassoPemFileType lasso_get_pem_file_type(const char *file);

xmlSecKeyPtr lasso_get_public_key_from_pem_file(const char *file);
xmlSecKeyPtr lasso_load_private_key_file(const char *file);
xmlSecKeyPtr lasso_get_public_key_from_pem_cert_file(const char *file);
xmlSecKeysMngr* lasso_load_certs_from_pem_certs_chain_file (const char *file);

char* lasso_query_sign(char *query, LassoSignatureMethod sign_method,
	const char *private_key_file, const char *private_key_password);

int lasso_query_verify_signature(const char *query, const xmlSecKey *public_key);

char* lasso_sha1(const char *str);

char** urlencoded_to_strings(const char *str);

int lasso_sign_node(xmlNode *xmlnode, const char *id_attr_name, const char *id_value,
		const char *private_key_file, const char *private_key_password,
		const char *certificate_file);

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
	xmlSecKey *encryption_public_key, LassoEncryptionSymKeyType encryption_sym_key_type);

int lasso_node_decrypt_xmlnode(xmlNode* encrypted_element, GList *encrypted_key,
		xmlSecKey *encryption_private_key, LassoNode **output);

xmlDocPtr lasso_xml_parse_memory(const char *buffer, int size);

char* lasso_concat_url_query(const char *url, const char *query);

xmlDocPtr lasso_xml_parse_memory(const char *buffer, int size);

xmlNode* lasso_xml_get_soap_content(xmlNode *root);

gboolean lasso_xml_is_soap(xmlNode *root);

void _debug(GLogLevelFlags level, const char *filename, int line,
		const char *function, const char *format, ...);

int error_code(GLogLevelFlags level, int error, ...);

#if defined(LASSO_DEBUG) && defined(__GNUC__)
#  define debug(format, args...) \
	_debug(G_LOG_LEVEL_DEBUG, __FILE__, __LINE__,__FUNCTION__, format, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define debug(...)     ;
#else
static inline void debug(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	va_end(ap);
}
#endif

#ifndef __FUNCTION__
#  define __FUNCTION__  ""
#endif

#if defined(__GNUC__)
#  define message(level, format, args...) \
	_debug(level, __FILE__, __LINE__, __FUNCTION__, format, ##args)
#elif defined(HAVE_VARIADIC_MACROS)
#  define message(level, ...) \
	_debug(level, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#else
static inline void message(GLogLevelFlags level, const char *format, ...)
{
	va_list ap;
	char s[1024];
	va_start(ap, format);
	g_vsnprintf(s, 1024, format, ap);
	va_end(ap);
	_debug(level, __FILE__, __LINE__, __FUNCTION__, s);
}
#endif

#define critical_error(rc) error_code(G_LOG_LEVEL_CRITICAL, rc)

#define IF_SAML2(profile) \
	if (lasso_provider_get_protocol_conformance(LASSO_PROVIDER(profile->server)) == \
			LASSO_PROTOCOL_SAML_2_0)

char * lasso_get_relaystate_from_query(const char *query);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_TOOLS_H__ */
