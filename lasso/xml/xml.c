/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/xml.h>
#include "../export.h"

struct _LassoNodePrivate
{
  gboolean    dispose_has_run;
  gchar      *type_name;
  xmlNodePtr  node;
};

/*****************************************************************************/
/* virtual public methods                                                    */
/*****************************************************************************/

GString *
lasso_node_build_query(LassoNode *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->build_query(node));
}

void
lasso_node_dump(LassoNode *node, const xmlChar *encoding, int format) {
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->dump(node, encoding, format);
}

LassoAttr *
lasso_node_get_attr(LassoNode *node, const xmlChar *name)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_attr(node, name));
}

xmlChar *
lasso_node_get_attr_value(LassoNode *node, const xmlChar *name)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_attr_value(node, name));
}

GPtrArray *
lasso_node_get_attrs(LassoNode *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_attrs(node));
}

LassoNode *
lasso_node_get_child(LassoNode *node, const xmlChar *name)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_child(node, name));
}

GPtrArray *
lasso_node_get_children(LassoNode *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_children(node));
}

/**
 * lasso_node_get_content:
 * @node: the LassoNode
 * 
 * Read the value of a node, this can be either the text carried directly by
 * this node if it's a TEXT node or the aggregate string of the values carried
 * by this node child's (TEXT and ENTITY_REF). Entity references are
 * substituted.
 * 
 * Return value: a new xmlChar * or NULL if no content is available.
 * It's up to the caller to free the memory with xmlFree().
 **/
xmlChar *
lasso_node_get_content(LassoNode *node)
{
  if (node != NULL) {
    LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
    return (class->get_content(node));
  }
  else {
    return (NULL);
  }
}

xmlChar *
lasso_node_get_name(LassoNode *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_name(node));
}

void
lasso_node_parse_memory(LassoNode *node,
			const char *buffer)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->parse_memory(node, buffer);
}

void
lasso_node_rename_prop(LassoNode *node,
		       const xmlChar *old_name,
		       const xmlChar *new_name)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->rename_prop(node, old_name, new_name);
}

GData *
lasso_node_serialize(LassoNode *node, GData *gd)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->serialize(node, gd));
}

gchar *
lasso_node_url_encode(LassoNode *node,
		      guint sign_method,
		      const gchar *key_file)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->url_encode(node, sign_method, key_file));
}

gint
lasso_node_verify_signature(LassoNode *node,
			    const gchar *certificate_file)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->verify_signature(node, certificate_file));
}

/*****************************************************************************/
/* virtual private methods                                                   */
/*****************************************************************************/

static void
lasso_node_add_child(LassoNode *node,
		     LassoNode *child,
		     gboolean unbounded)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(node, child, unbounded);
}

static xmlNodePtr
lasso_node_get_xmlNode(LassoNode *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_xmlNode(node));
}

/**
 * lasso_node_new_child:
 * @node: the pointer to node
 * @name: the name of the child
 * @content: the content
 * @unbounded: if TRUE, several children with the same name can be added else a
 * child is unique.
 * 
 * Add a new child in node.
 * This is an internal function and should not be called by application directly.
 **/
static void
lasso_node_new_child(LassoNode *node,
		     const xmlChar *name,
		     const xmlChar *content,
		     gboolean unbounded)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(node, name, content, unbounded);
}

static void
lasso_node_new_ns(LassoNode *node,
		  const xmlChar *href,
		  const xmlChar *prefix)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_ns(node, href, prefix);
}

static void
lasso_node_set_name(LassoNode *node,
		    const xmlChar *name)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_name(node, name);
}

static void
lasso_node_set_node(LassoNode *node,
		    xmlNodePtr libxml_node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_node(node, libxml_node);
}

static void
lasso_node_set_prop(LassoNode *node,
		    const xmlChar *name,
		    const xmlChar *value)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(node, name, value);
}

/*****************************************************************************/
/* implementation methods                                                    */
/*****************************************************************************/

static void
gdata_build_query_foreach_func(GQuark key_id,
			       gpointer data,
			       gpointer user_data) {
  guint i;
  GString *str;
  GPtrArray *array;

  array = g_ptr_array_new();
  str = g_string_new("");
  for (i=0; i<((GPtrArray *)data)->len; i++) {
    str = g_string_append(str, g_ptr_array_index((GPtrArray *)data, i));
    if (i<((GPtrArray *)data)->len - 1) {
      str = g_string_append(str, " ");
    }
    /* free each val get with xmlGetProp() in lasso_node_impl_serialize() */
    xmlFree(g_ptr_array_index((GPtrArray *)data, i));
  }
  g_ptr_array_add(array, (gpointer)g_quark_to_string(key_id));
  g_ptr_array_add(array, str->str);
  g_string_free(str, FALSE);
  g_ptr_array_add((GPtrArray *)user_data, array);
}

static GString *
lasso_node_impl_build_query(LassoNode *node)
{
  guint i;
  GData *gd;
  GPtrArray *a, *aa;
  GString *query;

  gd = lasso_node_serialize(node, NULL);
  a = g_ptr_array_new();
  /* transform dict into array
     each key => [val1, val2, ...] of dict become [key, "val1 val2 ..."] */
  g_datalist_foreach(&gd, gdata_build_query_foreach_func, a);
  
  query = g_string_new("");
  for (i=0; i<a->len; i++) {
    aa = g_ptr_array_index(a, i);
    query = g_string_append(query, g_ptr_array_index(aa, 0));
    query = g_string_append(query, "=");
    query = g_string_append(query, lasso_str_escape(g_ptr_array_index(aa, 1)));
    if (i<a->len - 1) {
      query = g_string_append(query, "&");
    }
    // free allocated memory
    g_ptr_array_free(aa, TRUE);
  }
  // free allocated memory
  g_ptr_array_free(a, TRUE);
  g_datalist_clear(&gd);

  return (query);
}

static void
lasso_node_impl_dump(LassoNode *node,
		     const xmlChar *encoding,
		     int format)
{
  xmlChar *ret;
  int len;
  xmlOutputBufferPtr buf;
  xmlCharEncodingHandlerPtr handler = NULL;

  if (encoding != NULL) {
    handler = xmlFindCharEncodingHandler(encoding);
    if (handler == NULL) {
      return;
    }
  }
  buf = xmlAllocOutputBuffer(handler);
  if (buf == NULL) {
    return;
  }
  xmlNodeDumpOutput(buf, node->private->node->doc, node->private->node,
		    0, format, encoding);
  xmlOutputBufferFlush(buf);
  if (buf->conv != NULL) {
    len = buf->conv->use;
    ret = buf->conv->content;
    buf->conv->content = NULL;
  }
  else {
    len = buf->buffer->use;
    ret = buf->buffer->content;
    buf->buffer->content = NULL;
  }
  (void) xmlOutputBufferClose(buf);

  printf("%s\n\n", ret);
}

static LassoAttr*
lasso_node_impl_get_attr(LassoNode *node, const xmlChar *name)
{
  LassoAttr *prop;

  prop = node->private->node->properties;
  while (prop != NULL) {
    if (xmlStrEqual(prop->name, name)) {
      return (prop);
    }
    prop = prop->next;
  }

  return (NULL);
}

static xmlChar *
lasso_node_impl_get_attr_value(LassoNode *node, const xmlChar *name)
{
  return (lasso_node_get_attr(node, name)->children->content);
}

static GPtrArray *
lasso_node_impl_get_attrs(LassoNode *node)
{
  GPtrArray *attributs;
  LassoAttr *prop;

  attributs = g_ptr_array_new();
  
  prop = node->private->node->properties;
  while (prop != NULL) {
    g_ptr_array_add(attributs, prop);
    prop = prop->next;
  }

  return (attributs);
}

static LassoNode *
lasso_node_impl_get_child(LassoNode *node,
			  const xmlChar *name)
{
  xmlNodePtr cur;
  
  cur = node->private->node->children;
  while (cur != NULL) {
    if(cur->type == XML_ELEMENT_NODE) {
      if (xmlStrEqual(cur->name, name)) {
	return (lasso_node_new(cur));
      }
    }
    cur = cur->next;
  }
  return (NULL);
}

static GPtrArray *
lasso_node_impl_get_children(LassoNode *node)
{
  GPtrArray *children = NULL;
  xmlNodePtr cur;

  cur = node->private->node->children;
  if (cur != NULL)
    children = g_ptr_array_new();
  
  while (cur != NULL) {
    g_ptr_array_add(children, lasso_node_new(cur));
    cur = cur->next;
  }

  return (children);
}

static xmlChar *
lasso_node_impl_get_content(LassoNode *node)
{
  return (xmlNodeGetContent(node->private->node));
}

static xmlChar *
lasso_node_impl_get_name(LassoNode *node)
{
  return ((xmlChar *)(node->private->node->name));
}

void
lasso_node_impl_parse_memory(LassoNode *node,
			     const char *buffer)
{
  xmlDocPtr doc;
  xmlNodePtr root;

  doc = xmlParseMemory(buffer, streln(buffer));
  root = xmlDocGetRootElement(doc);
  xmlFreeNode(node->private->node);
  node->private->node = root;
}

static void
lasso_node_impl_rename_prop(LassoNode *node,
			    const xmlChar *old_name,
			    const xmlChar *new_name)
{
  xmlChar *value;
  LassoAttr *prop;

  value = xmlGetProp(node->private->node, old_name);
  if (value != NULL) {
    xmlRemoveProp(lasso_node_get_attr(node, old_name));
    lasso_node_set_prop(node, new_name, value);
  }
}

static GData *
lasso_node_impl_serialize(LassoNode *node, GData *gd)
{
  GPtrArray *attrs, *children;
  GPtrArray *values;
  xmlChar *name, *val;
  int i;

  if (gd == NULL) {
    g_datalist_init(&gd);
  }

  attrs = lasso_node_get_attrs(node);
  for(i=0; i<attrs->len; i++) {
    values = g_ptr_array_new();
    name = (xmlChar *)((LassoAttr *)g_ptr_array_index(attrs, i))->name;
    /* val must be xmlFree() */
    val = xmlGetProp(node->private->node, name);
    g_ptr_array_add(values, val);
    g_datalist_set_data(&gd, name, values);
  }
  g_ptr_array_free(attrs, TRUE);

  children = lasso_node_get_children(node);
  if (children != NULL) {
    for(i=0; i<children->len; i++) {
      xmlNodePtr xml_node = ((LassoNode *)g_ptr_array_index(children, i))->private->node;
      switch (xml_node->type) {
      case XML_ELEMENT_NODE:
	gd = lasso_node_serialize(g_ptr_array_index(children, i), gd);
	break;
      case XML_TEXT_NODE:
	name   = lasso_node_get_name(node);
	values = (GPtrArray *)g_datalist_get_data(&gd, name);
	if (values == NULL) {
	  values = g_ptr_array_new();
	}
	/* val must be xmlFree() */
	val = xmlNodeGetContent(node->private->node);
	g_ptr_array_add(values, val);
	g_datalist_set_data(&gd, name, values);
	break;
      }
    }
  }
  g_ptr_array_free(children, TRUE);
    
  return (gd);
}

static gchar *
lasso_node_impl_url_encode(LassoNode *node,
			   guint sign_method,
			   const gchar *key_file)
{
  GString *msg;
  xmlDocPtr doc;
  xmlChar *str1, *str2;
  gchar *ret;

  msg = lasso_node_build_query(node);

  if (sign_method > 0 && key_file != NULL) {
    switch (sign_method) {
    case lassoUrlEncodeRsaSha1:
      msg = g_string_append(msg, "&SigAlg=");
      msg = g_string_append(msg, lasso_str_escape("http://www.w3.org/2000/09/xmldsig#rsa-sha1"));
      doc = lasso_str_sign(msg->str, xmlSecTransformRsaSha1Id, key_file);
      msg = g_string_append(msg, "&Signature=");
      str1 = lasso_doc_get_node_content(doc, xmlSecNodeSignatureValue);
      str2 = lasso_str_escape(str1);
      xmlFree(str1);
      msg = g_string_append(msg, str2);
      xmlFree(str2);
      break;
    case lassoUrlEncodeDsaSha1:
      msg = g_string_append(msg, "&SigAlg=");
      msg = g_string_append(msg, lasso_str_escape("http://www.w3.org/2000/09/xmldsig#dsa-sha1"));
      doc = lasso_str_sign(msg->str, xmlSecTransformDsaSha1Id, key_file);
      msg = g_string_append(msg, "&Signature=");
      str1 = lasso_doc_get_node_content(doc, xmlSecNodeSignatureValue);
      str2 = lasso_str_escape(str1);
      xmlFree(str1);
      msg = g_string_append(msg, str2);
      xmlFree(str2);
      break;
    }
  }

  ret = g_strdup(msg->str);
  g_string_free(msg, TRUE);
  return (ret);
}

gint
lasso_node_impl_verify_signature(LassoNode *node,
				 const gchar *certificate_file)
{
  xmlNodePtr signature;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  gint ret = -1;

  /* find start node */
  signature = xmlSecFindNode(node->private->node, xmlSecNodeSignature,
			     xmlSecDSigNs);
  if (signature == NULL) {
    fprintf(stderr, "Error: start node not found\n");
    goto done;	
  }

  /* create simple keys mngr */
  mngr = xmlSecKeysMngrCreate();
  if (mngr == NULL) {
    fprintf(stderr, "Error: failed to create keys manager.\n");
    goto done;
  }

  if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    fprintf(stderr, "Error: failed to initialize keys manager.\n");
    goto done;
  }
  
  /* load trusted cert */
  if (xmlSecCryptoAppKeysMngrCertLoad(mngr, certificate_file,
				      xmlSecKeyDataFormatPem,
				      xmlSecKeyDataTypeTrusted) < 0) {
    fprintf(stderr, "Error: failed to load pem certificate from \"%s\"\n",
	    certificate_file);
    goto done;
  }

  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  if (dsigCtx == NULL) {
    fprintf(stderr, "Error: failed to create signature context\n");
    goto done;
  }

  /* verify signature */
  if (xmlSecDSigCtxVerify(dsigCtx, signature) < 0) {
    fprintf(stderr, "Error: signature verify\n");
    goto done;
  }

  /* print verification result to stdout */
  if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
    fprintf(stdout, "Signature is OK\n");
    ret = 1;
  }
  else {
    fprintf(stdout, "Signature is INVALID\n");
    ret = 0;
  }

 done:
  /* cleanup */
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  if(mngr != NULL) {
    xmlSecKeysMngrDestroy(mngr);
  }
  return (ret);
}

/*** private methods *********************************************************/

static void
lasso_node_impl_add_child(LassoNode *node,
			  LassoNode *child,
			  gboolean unbounded)
{
  LassoNode *old_child;
  
  // if child is not unbounded, we search it
  if (!unbounded) {
    old_child = lasso_node_get_child(node, child->private->node->name);
  }

  if (!unbounded && old_child != NULL) {
    // child replace old child
    xmlReplaceNode(old_child->private->node, child->private->node);
  }
  else {
    // else child is added
    xmlAddChild(node->private->node, child->private->node);
  }
}

static xmlNodePtr
lasso_node_impl_get_xmlNode(LassoNode *node)
{
  return (node->private->node);
}

static void
lasso_node_impl_new_child(LassoNode *node,
			  const xmlChar *name,
			  const xmlChar *content,
			  gboolean unbounded)
{
  LassoNode *old_child;
  
  if (!unbounded) {
    old_child = lasso_node_get_child(node, name);
  }

  if (!unbounded && old_child != NULL)
    xmlNodeSetContent(old_child->private->node, content);
  else {
    xmlNewChild(node->private->node, NULL, name, content);
  }
}

static void
lasso_node_impl_new_ns(LassoNode *node,
		       const xmlChar *href,
		       const xmlChar *prefix)
{
  xmlSetNs(node->private->node,
	   xmlNewNs(node->private->node, href, prefix));
}

static void
lasso_node_impl_set_name(LassoNode *node,
			 const xmlChar *name)
{
  xmlNodeSetName(node->private->node, name);
  node->private->type_name = xmlStrdup(name);
}

static void
lasso_node_impl_set_node(LassoNode *node,
			 xmlNodePtr libxml_node)
{
  xmlFreeNode(node->private->node);
  node->private->node = libxml_node;
}

static void
lasso_node_impl_set_prop(LassoNode *node,
			 const xmlChar *name,
			 const xmlChar *value)
{
  xmlSetProp(node->private->node, name, value);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_node_instance_init(LassoNode *instance)
{
  LassoNode *node = LASSO_NODE(instance);

  node->private = g_new (LassoNodePrivate, 1);
  node->private->dispose_has_run = FALSE;
  node->private->type_name = NULL;
  node->private->node = xmlNewNode(NULL, "no-name-set");
}

/* overrided parent class methods */

static void
lasso_node_dispose(LassoNode *node)
{
  if (node->private->dispose_has_run) {
    return;
  }
  node->private->dispose_has_run = TRUE;

  /* unref reference counted objects */
  /* we don't have any here */
  g_print("%s 0x%x disposed ...\n", node->private->type_name, node);
}

static void
lasso_node_finalize(LassoNode *node)
{
  g_print("%s 0x%x finalized ...\n", node->private->type_name, node);
  g_free (node->private->type_name);
  xmlFreeNode(node->private->node);
}

static void
lasso_node_class_init(LassoNodeClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  /* virtual public methods */
  class->build_query      = lasso_node_impl_build_query;
  class->dump             = lasso_node_impl_dump;
  class->get_attr         = lasso_node_impl_get_attr;
  class->get_attr_value   = lasso_node_impl_get_attr_value;
  class->get_attrs        = lasso_node_impl_get_attrs;
  class->get_child        = lasso_node_impl_get_child;
  class->get_children     = lasso_node_impl_get_children;
  class->get_content      = lasso_node_impl_get_content;
  class->get_name         = lasso_node_impl_get_name;
  class->parse_memory     = lasso_node_impl_parse_memory;
  class->rename_prop      = lasso_node_impl_rename_prop;
  class->serialize        = lasso_node_impl_serialize;
  class->url_encode       = lasso_node_impl_url_encode;
  class->verify_signature = lasso_node_impl_verify_signature;
  /* virtual private methods */
  class->add_child    = lasso_node_impl_add_child;
  class->get_xmlNode  = lasso_node_impl_get_xmlNode;
  class->new_child    = lasso_node_impl_new_child;
  class->new_ns       = lasso_node_impl_new_ns;
  class->set_name     = lasso_node_impl_set_name;
  class->set_node     = lasso_node_impl_set_node;
  class->set_prop     = lasso_node_impl_set_prop;
  /* override parent class methods */
  gobject_class->dispose  = (void *)lasso_node_dispose;
  gobject_class->finalize = (void *)lasso_node_finalize;
}

GType lasso_node_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoNodeClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_node_class_init,
      NULL,
      NULL,
      sizeof(LassoNode),
      0,
      (GInstanceInitFunc) lasso_node_instance_init,
    };
    
    this_type = g_type_register_static(G_TYPE_OBJECT , "LassoNode",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_node_new(xmlNodePtr node) {
  LassoNode *lasso_node;

  lasso_node = LASSO_NODE(g_object_new(LASSO_TYPE_NODE, NULL));

  if (node != NULL) {
    xmlFreeNode(lasso_node->private->node);
    lasso_node->private->node = node;
  }

  return (lasso_node);
}
