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

#include <lasso/xml/strings.h>
#include <lasso/xml/tools.h>

#define LASSO_TYPE_NODE (lasso_node_get_type())
#define LASSO_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NODE, LassoNode))
#define LASSO_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NODE, LassoNodeClass))
#define LASSO_IS_NODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NODE))
#define LASSO_IS_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NODE))
#define LASSO_NODE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NODE, LassoNodeClass)) 

typedef enum {
	LASSO_MESSAGE_FORMAT_UNKNOWN = 0,
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

typedef struct _xmlAttr LassoAttr;

typedef struct _LassoNode LassoNode;
typedef struct _LassoNodeClass LassoNodeClass;
typedef struct _LassoNodePrivate LassoNodePrivate;

/**
 * _LassoNode:
 * @parent: the parent object
 * @private: private pointer structure
 **/
struct _LassoNode {
	GObject parent;
	/*< private >*/
	LassoNodePrivate *private;
};

struct _LassoNodeClass {
	GObjectClass parent_class;
	/*< vtable >*/
	/*< public >*/
	LassoNode*     (* copy)                  (LassoNode     *node);
	void           (* destroy)               (LassoNode     *node);
	gchar*         (* export_to_base64)      (LassoNode     *node);
	gchar*         (* export_to_query)       (LassoNode     *node,
			lassoSignatureMethod  sign_method,
			const gchar          *private_key_file);
	gint           (* verify_signature)      (LassoNode   *node,
			const gchar *public_key_file,
			const gchar *ca_cert_chain_file);
	/*< private >*/
	gchar*     (* build_query)        (LassoNode     *node);
	void       (* init_from_query)    (LassoNode     *node, char **query_fields);
	void       (* init_from_xml)      (LassoNode     *node, xmlNode *xmlnode);
	xmlNodePtr (* get_xmlNode)        (LassoNode     *node);
};

LASSO_EXPORT GType      lasso_node_get_type              (void);

LASSO_EXPORT LassoNode* lasso_node_new                   (void);
LASSO_EXPORT LassoNode* lasso_node_new_from_dump         (const gchar *buffer);
LASSO_EXPORT LassoNode* lasso_node_new_from_soap(const gchar *soap);
LASSO_EXPORT LassoNode* lasso_node_new_from_xmlNode      (xmlNodePtr node);

LASSO_EXPORT LassoNode* lasso_node_copy                  (LassoNode *node);

LASSO_EXPORT void       lasso_node_destroy               (LassoNode *node);

LASSO_EXPORT gchar*     lasso_node_dump                  (LassoNode     *node,
							  const xmlChar *encoding,
							  int            format);

LASSO_EXPORT gchar* lasso_node_build_query(LassoNode *node);

LASSO_EXPORT gchar*     lasso_node_export_to_base64      (LassoNode *node);

LASSO_EXPORT gchar*     lasso_node_export_to_query       (LassoNode            *node,
							  lassoSignatureMethod  sign_method,
							  const gchar          *private_key_file);

LASSO_EXPORT gchar*     lasso_node_export_to_soap        (LassoNode *node);

LASSO_EXPORT LassoMessageFormat lasso_node_init_from_message(LassoNode *node, const char *message);
LASSO_EXPORT void       lasso_node_init_from_query       (LassoNode   *node,
							  const gchar *query);
LASSO_EXPORT void       lasso_node_init_from_xml         (LassoNode *node, xmlNode *xmlnode);

LASSO_EXPORT gint       lasso_node_verify_signature      (LassoNode   *node,
							  const gchar *public_key_file,
							  const gchar *ca_cert_chain_file);

LASSO_EXPORT xmlNodePtr lasso_node_get_xmlNode(LassoNode *node);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_H__ */
