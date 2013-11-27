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

#ifndef __LASSO_XML_H__
#define __LASSO_XML_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <string.h>

#include <glib.h>
#include <glib-object.h>

#include <libxml/uri.h>
#include <libxml/tree.h>

#include "../export.h"
#include "../errors.h"
#include "strings.h"

#define LASSO_TYPE_NODE (lasso_node_get_type())
#define LASSO_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NODE, LassoNode))
#define LASSO_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NODE, LassoNodeClass))
#define LASSO_IS_NODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NODE))
#define LASSO_IS_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NODE))
#define LASSO_NODE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NODE, LassoNodeClass))

/**
 * LassoMessageFormat:
 * @LASSO_MESSAGE_FORMAT_ERROR: error while determining format
 * @LASSO_MESSAGE_FORMAT_UNKNOWN: unknown format
 * @LASSO_MESSAGE_FORMAT_XML: XML
 * @LASSO_MESSAGE_FORMAT_BASE64: base-64 encoded
 * @LASSO_MESSAGE_FORMAT_QUERY: query string
 * @LASSO_MESSAGE_FORMAT_SOAP: SOAP
 *
 * Return code for lasso_node_init_from_message; it describes the type of the
 * message that was passed to that function.
 **/
typedef enum {
	LASSO_MESSAGE_FORMAT_XSCHEMA_ERROR = -2,
	LASSO_MESSAGE_FORMAT_ERROR = -1,
	LASSO_MESSAGE_FORMAT_UNKNOWN,
	LASSO_MESSAGE_FORMAT_XML,
	LASSO_MESSAGE_FORMAT_BASE64,
	LASSO_MESSAGE_FORMAT_QUERY,
	LASSO_MESSAGE_FORMAT_SOAP
} LassoMessageFormat;


/**
 * LassoSignatureType:
 * @LASSO_SIGNATURE_TYPE_NONE: no signature
 * @LASSO_SIGNATURE_TYPE_SIMPLE: sign with the private key, copy the public part in the signature.
 * @LASSO_SIGNATURE_TYPE_WITHX509: sign with the private key, copy the associated certificat in the
 * signature.
 *
 * Signature type.
 **/
typedef enum {
	LASSO_SIGNATURE_TYPE_NONE = 0,
	LASSO_SIGNATURE_TYPE_SIMPLE,
	LASSO_SIGNATURE_TYPE_WITHX509,
	LASSO_SIGNATURE_TYPE_LAST
} LassoSignatureType;


/**
 * LassoSignatureMethod:
 * @LASSO_SIGNATURE_METHOD_RSA_SHA1: sign using a RSA private key
 * @LASSO_SIGNATURE_METHOD_DSA_SHA1: sign using a DSA private key
 * @LASSO_SIGNATURE_METHOD_HMAC_SHA1: sign using a an HMAC-SHA1 secret key
 *
 * Signature method.
 **/
typedef enum {
	LASSO_SIGNATURE_METHOD_NONE = 0,
	LASSO_SIGNATURE_METHOD_RSA_SHA1,
	LASSO_SIGNATURE_METHOD_DSA_SHA1,
	LASSO_SIGNATURE_METHOD_HMAC_SHA1,
	LASSO_SIGNATURE_METHOD_LAST
} LassoSignatureMethod;

static inline gboolean
lasso_validate_signature_method(LassoSignatureMethod signature_method)
{
	return signature_method > (LassoSignatureMethod)LASSO_SIGNATURE_TYPE_NONE \
		&& signature_method < (LassoSignatureMethod)LASSO_SIGNATURE_METHOD_LAST;
}

typedef struct _LassoNode LassoNode;
typedef struct _LassoNodeClass LassoNodeClass;
typedef struct _LassoNodeClassData LassoNodeClassData;

/**
 * LassoNode:
 *
 * Base type for all XML contents, or for object using serialization to XML.
 **/
struct _LassoNode {
	GObject parent;
};

struct _LassoNodeClass {
	GObjectClass parent_class;
	LassoNodeClassData *node_data;

	void     (* destroy)            (LassoNode *node);
	char*    (* build_query)        (LassoNode *node);
	gboolean (* init_from_query)    (LassoNode *node, char **query_fields);
	int      (* init_from_xml)      (LassoNode *node, xmlNode *xmlnode);
	xmlNode* (* get_xmlNode)        (LassoNode *node, gboolean lasso_dump);
};

LASSO_EXPORT GType lasso_node_get_type(void);

LASSO_EXPORT LassoNode* lasso_node_new(void);
LASSO_EXPORT LassoNode* lasso_node_new_from_dump(const char *dump);
LASSO_EXPORT LassoNode* lasso_node_new_from_soap(const char *soap);
LASSO_EXPORT LassoNode* lasso_node_new_from_xmlNode(xmlNode* node);

LASSO_EXPORT void lasso_node_cleanup_original_xmlnodes(LassoNode *node);
LASSO_EXPORT void lasso_node_destroy(LassoNode *node);
LASSO_EXPORT char* lasso_node_dump(LassoNode *node);
LASSO_EXPORT char* lasso_node_export_to_base64(LassoNode *node);

LASSO_EXPORT char* lasso_node_export_to_query(LassoNode *node,
		LassoSignatureMethod sign_method, const char *private_key_file);

LASSO_EXPORT char* lasso_node_export_to_query_with_password(LassoNode *node,
		LassoSignatureMethod sign_method, const char *private_key_file,
		const char *private_key_file_password);

LASSO_EXPORT char* lasso_node_export_to_soap(LassoNode *node);

LASSO_EXPORT gchar* lasso_node_export_to_xml(LassoNode *node);

LASSO_EXPORT char* lasso_node_export_to_paos_request(LassoNode *node, const char *issuer,
				const char *responseConsumerURL, const char *relay_state);

LASSO_EXPORT char* lasso_node_export_to_ecp_soap_response(LassoNode *node,
				const char *assertionConsumerURL);

LASSO_EXPORT xmlNode* lasso_node_get_xmlNode(LassoNode *node, gboolean lasso_dump);

LASSO_EXPORT xmlNode* lasso_node_get_original_xmlnode(LassoNode *node);

LASSO_EXPORT void lasso_node_set_original_xmlnode(LassoNode *node, xmlNode* xmlnode);

LASSO_EXPORT void lasso_node_set_custom_namespace(LassoNode *node, const char *prefix,
		const char *href);

LASSO_EXPORT void lasso_node_set_custom_nodename(LassoNode *node, const char *nodename);

LASSO_EXPORT const char* lasso_node_get_name(LassoNode *node);

LASSO_EXPORT const char* lasso_node_get_namespace(LassoNode *node);

LASSO_EXPORT LassoMessageFormat lasso_node_init_from_message(LassoNode *node, const char *message);

LASSO_EXPORT gboolean lasso_node_init_from_query(LassoNode *node, const char *query);
LASSO_EXPORT lasso_error_t lasso_node_init_from_xml(LassoNode *node, xmlNode *xmlnode);

LASSO_EXPORT void lasso_register_dst_service(const char *prefix, const char *href);

LASSO_EXPORT char* lasso_get_prefix_for_dst_service_href(const char *href);

LASSO_EXPORT void lasso_register_idwsf2_dst_service(const gchar *prefix, const gchar *href);

LASSO_EXPORT gchar* lasso_get_prefix_for_idwsf2_dst_service_href(const gchar *href);

LASSO_EXPORT char* lasso_node_debug(LassoNode *node, int level);

struct _LassoKey;

LASSO_EXPORT char* lasso_node_export_to_saml2_query(LassoNode *node, const char *param_name, const
		char *url, struct _LassoKey *key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_H__ */
