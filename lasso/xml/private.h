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

#ifndef __LASSO_TOOLS_H__
#define __LASSO_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <xmlsec/crypto.h>

#ifndef HAVE_VSNPRINTF
int vsnprintf (char *str, size_t count, const char *fmt, va_list args);
#endif


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

	/* transformers for content transformation */
	SNIPPET_STRING  = 1 << 0, /* default, can be omitted */
	SNIPPET_BOOLEAN = 1 << 20,
	SNIPPET_INTEGER = 1 << 21,
	SNIPPET_LASSO_DUMP = 1 << 22,
	SNIPPET_OPTIONAL = 1 << 23, /* optional, ignored if 0 */
	SNIPPET_OPTIONAL_NEG = 1 << 24, /* optional, ignored if -1 */
} SnippetType;

struct XmlSnippet {
	char *name;
	SnippetType type;
	guint offset;
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
};

void lasso_node_class_set_nodename(LassoNodeClass *klass, char *name);
void lasso_node_class_set_ns(LassoNodeClass *klass, char *href, char *prefix);
void lasso_node_class_add_snippets(LassoNodeClass *klass, struct XmlSnippet *snippets);
void lasso_node_class_add_query_snippets(LassoNodeClass *klass, struct QuerySnippet *snippets);

gchar* lasso_node_build_query_from_snippets(LassoNode *node);
gboolean lasso_node_init_from_query_fields(LassoNode *node, char **query_fields);



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

xmlSecKey* lasso_get_public_key_from_pem_cert_file(const char *file);
xmlSecKeysMngr* lasso_load_certs_from_pem_certs_chain_file (const char *file);

xmlChar* lasso_query_sign(xmlChar *query,
		LassoSignatureMethod sign_method, const char *private_key_file);

int lasso_query_verify_signature(const char *query, const char *sender_public_key_file);

char* lasso_sha1(const char *str);

char** urlencoded_to_strings(const char *str);

int lasso_sign_node(xmlNode *xmlnode, const char *id_attr_name, const char *id_value,
		const char *private_key_file, const char *certificate_file);

void xmlCleanNs(xmlNode *root_node);

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
	vsnprintf(s, 1024, format, ap);
	va_end(ap);
	_debug(level, __FILE__, __LINE__, __FUNCTION__, s);
}
#endif

#define critical_error(rc) error_code(G_LOG_LEVEL_CRITICAL, rc)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_TOOLS_H__ */
