/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_XML_H__
#define __LASSO_XML_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <string.h>

#include <glib.h>
#include <glib-object.h>
#include <glib/gprintf.h>

#include <libxml/uri.h>
#include <libxml/tree.h>

#include <lasso/export.h>
#include <lasso/xml/errors.h>
#include <lasso/xml/strings.h>

#define LASSO_TYPE_NODE (lasso_node_get_type())
#define LASSO_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NODE, LassoNode))
#define LASSO_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NODE, LassoNodeClass))
#define LASSO_IS_NODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NODE))
#define LASSO_IS_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NODE))
#define LASSO_NODE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NODE, LassoNodeClass))

typedef enum {
	LASSO_MESSAGE_FORMAT_ERROR = -1,
	LASSO_MESSAGE_FORMAT_UNKNOWN,
	LASSO_MESSAGE_FORMAT_XML,
	LASSO_MESSAGE_FORMAT_BASE64,
	LASSO_MESSAGE_FORMAT_QUERY,
	LASSO_MESSAGE_FORMAT_SOAP
} LassoMessageFormat;

typedef enum {
	LASSO_SIGNATURE_TYPE_NONE = 0,
	LASSO_SIGNATURE_TYPE_SIMPLE,
	LASSO_SIGNATURE_TYPE_WITHX509
} lassoSignatureType;

typedef enum {
	LASSO_SIGNATURE_METHOD_RSA_SHA1 = 1,
	LASSO_SIGNATURE_METHOD_DSA_SHA1
} lassoSignatureMethod;

typedef struct _LassoNode LassoNode;
typedef struct _LassoNodeClass LassoNodeClass;
typedef struct _LassoNodeClassData LassoNodeClassData;

/**
 * _LassoNode:
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

	char*    (* get_sign_attr_name) ();
};

LASSO_EXPORT GType lasso_node_get_type(void);

LASSO_EXPORT LassoNode* lasso_node_new(void);
LASSO_EXPORT LassoNode* lasso_node_new_from_dump(const char *dump);
LASSO_EXPORT LassoNode* lasso_node_new_from_soap(const char *soap);
LASSO_EXPORT LassoNode* lasso_node_new_from_xmlNode(xmlNode* node);

LASSO_EXPORT void lasso_node_destroy(LassoNode *node);
LASSO_EXPORT char* lasso_node_dump(LassoNode *node, const char *encoding, int format);
LASSO_EXPORT char* lasso_node_build_query(LassoNode *node);
LASSO_EXPORT char* lasso_node_export_to_base64(LassoNode *node,
		const char *private_key_file, const char *certificate_file);

LASSO_EXPORT char* lasso_node_export_to_query(LassoNode *node,
		lassoSignatureMethod  sign_method, const char *private_key_file);

LASSO_EXPORT char* lasso_node_export_to_soap(LassoNode *node,
		const char *private_key_file, const char *certificate_file);

LASSO_EXPORT xmlNode* lasso_node_get_xmlNode(LassoNode *node, gboolean lasso_dump);

LASSO_EXPORT LassoMessageFormat lasso_node_init_from_message(LassoNode *node, const char *message);
LASSO_EXPORT gboolean lasso_node_init_from_query(LassoNode *node, const char *query);
LASSO_EXPORT int lasso_node_init_from_xml(LassoNode *node, xmlNode *xmlnode);

LASSO_EXPORT gint lasso_node_verify_signature(LassoNode *node,
		const char *public_key_file, const char *ca_cert_chain_file);

#ifdef LASSO_INTERNALS
#include <lasso/xml/internals.h>
#include <lasso/xml/tools.h>
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_H__ */
