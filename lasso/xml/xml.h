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
  lassoNodeExportTypeXml = 1,
  lassoNodeExportTypeBase64,
  lassoNodeExportTypeQuery,
  lassoNodeExportTypeSoap
} lassoNodeExportTypes;

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
  LassoNode*     (* copy)             (LassoNode     *node);
  void           (* destroy)          (LassoNode     *node);
  xmlChar*       (* dump)             (LassoNode     *node,
				       const xmlChar *encoding,
				       int            format);
  xmlChar*       (* export)           (LassoNode     *node);
  xmlChar*       (* export_to_base64) (LassoNode     *node);
  gchar*         (* export_to_query)  (LassoNode            *node,
				       lassoSignatureMethod  sign_method,
				       const gchar          *private_key_file);
  xmlChar*       (* export_to_soap)   (LassoNode     *node);
  LassoAttr*     (* get_attr)         (LassoNode      *node,
				       const xmlChar  *name,
				       GError        **err);
  xmlChar*       (* get_attr_value)   (LassoNode      *node,
				       const xmlChar  *name,
				       GError        **err);
  GPtrArray*     (* get_attrs)        (LassoNode     *node);
  LassoNode*     (* get_child)        (LassoNode      *node,
				       const xmlChar  *name,
				       const xmlChar  *href,
				       GError        **err);
  xmlChar*       (* get_child_content)(LassoNode      *node,
				       const xmlChar  *name,
				       const xmlChar  *href,
				       GError        **err);
  GPtrArray*     (* get_children)     (LassoNode     *node);
  xmlChar*       (* get_content)      (LassoNode      *node,
				       GError        **err);
  xmlChar*       (* get_name)         (LassoNode     *node);
  void           (* import)           (LassoNode     *node,
                                       const xmlChar *buffer);
  void           (* import_from_node) (LassoNode     *node,
                                       LassoNode     *imported_node);
  void           (* rename_prop)      (LassoNode     *node,
				       const xmlChar *old_name,
				       const xmlChar *new_name);
  gint           (* verify_signature) (LassoNode     *node,
				       const gchar   *certificate_file,
				       GError       **err);
  /*< private >*/
  void       (* add_child)     (LassoNode     *node,
				LassoNode     *child,
				gboolean       unbounded);
  gint       (* add_signature) (LassoNode      *node,
				gint            sign_method,
				const xmlChar  *private_key_file,
				const xmlChar  *certificate_file,
				GError        **err);
  gchar*     (* build_query)   (LassoNode     *node);
  xmlNodePtr (* get_xmlNode)   (LassoNode     *node);
  void       (* new_child)     (LassoNode     *node,
				const xmlChar *name,
				const xmlChar *content,
				gboolean       unbounded);
  GData*     (* serialize)     (LassoNode     *node,
				GData         *gd);
  void       (* set_name)      (LassoNode     *node,
				const xmlChar *name);
  void       (* set_ns)        (LassoNode     *node,
				const xmlChar *href,
				const xmlChar *prefix);
  void       (* set_prop)      (LassoNode     *node,
				const xmlChar *name,
				const xmlChar *value);
  void       (* set_xmlNode)   (LassoNode     *node,
				xmlNodePtr     libxml_node);
};

LASSO_EXPORT GType          lasso_node_get_type         (void);

LASSO_EXPORT LassoNode*     lasso_node_new              (void);
LASSO_EXPORT LassoNode*     lasso_node_new_from_dump    (const xmlChar *buffer);
LASSO_EXPORT LassoNode*     lasso_node_new_from_xmlNode (xmlNodePtr node);

LASSO_EXPORT LassoNode*     lasso_node_copy             (LassoNode *node);

LASSO_EXPORT void           lasso_node_destroy          (LassoNode *node);

LASSO_EXPORT xmlChar*       lasso_node_dump             (LassoNode     *node,
							 const xmlChar *encoding,
							 int            format);

LASSO_EXPORT xmlChar*       lasso_node_export           (LassoNode *node);

LASSO_EXPORT xmlChar*       lasso_node_export_to_base64 (LassoNode *node);

LASSO_EXPORT gchar*         lasso_node_export_to_query  (LassoNode            *node,
							 lassoSignatureMethod  sign_method,
							 const gchar          *private_key_file);

LASSO_EXPORT xmlChar*       lasso_node_export_to_soap   (LassoNode *node);

LASSO_EXPORT LassoAttr*     lasso_node_get_attr         (LassoNode      *node,
							 const xmlChar  *name,
							 GError        **err);

LASSO_EXPORT xmlChar*       lasso_node_get_attr_value   (LassoNode      *node,
							 const xmlChar  *name,
							 GError        **err);

LASSO_EXPORT GPtrArray*     lasso_node_get_attrs        (LassoNode *node);

LASSO_EXPORT LassoNode*     lasso_node_get_child        (LassoNode      *node,
							 const xmlChar  *name,
							 const xmlChar  *href,
							 GError        **err);

LASSO_EXPORT xmlChar *      lasso_node_get_child_content(LassoNode      *node,
							 const xmlChar  *name,
							 const xmlChar  *href,
							 GError        **err);

LASSO_EXPORT GPtrArray*     lasso_node_get_children     (LassoNode *node);

LASSO_EXPORT xmlChar*       lasso_node_get_content      (LassoNode  *node,
							 GError    **err);

LASSO_EXPORT xmlChar*       lasso_node_get_name         (LassoNode *node);

LASSO_EXPORT void           lasso_node_import           (LassoNode     *node,
							 const xmlChar *buffer);

LASSO_EXPORT void           lasso_node_import_from_node (LassoNode *node,
							 LassoNode *imported_node);

LASSO_EXPORT void           lasso_node_rename_prop      (LassoNode     *node,
							 const xmlChar *old_name,
							 const xmlChar *new_name);

LASSO_EXPORT gint           lasso_node_verify_signature (LassoNode    *node,
							 const gchar  *certificate_file,
							 GError      **err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_H__ */
