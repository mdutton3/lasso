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

#include <string.h>

#include <xmlsec/base64.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/xml/errors.h>
#include <lasso/xml/xml.h>
#include <lasso/xml/ds_signature.h>

struct _LassoNodePrivate
{
  gboolean   dispose_has_run;
  gboolean   node_is_weak_ref;
  xmlNodePtr node;
};

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* virtual public methods                                                    */
/*****************************************************************************/

static void lasso_node_impl_set_xmlNode(LassoNode  *node, xmlNodePtr libxml_node);

/**
 * lasso_node_copy:
 * @node: a LassoNode
 * 
 * Build a copy of the node.
 * 
 * Return value: a copy of the node
 **/
LassoNode *
lasso_node_copy(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->copy(node));
}

/**
 * lasso_node_dump:
 * @node: a LassoNode
 * @encoding: the name of the encoding to use or NULL.
 * @format: is formatting allowed
 * 
 * Dumps @node. All datas in object are dumped in an XML format.
 * 
 * Return value: a full XML dump of @node
 **/
xmlChar *
lasso_node_dump(LassoNode     *node,
		const xmlChar *encoding,
		int            format)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->dump(node, encoding, format));
}

/**
 * lasso_node_destroy:
 * @node: a LassoNode
 * 
 * Destroys the LassoNode.
 **/
void
lasso_node_destroy(LassoNode *node)
{
  if (LASSO_IS_NODE(node)) {
    LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
    class->destroy(node);
  }
}

/**
 * lasso_node_export:
 * @node: a LassoNode
 * 
 * Exports the LassoNode.
 * 
 * Return value: an XML dump of the LassoNode (UTF-8 encoding)
 **/
xmlChar *
lasso_node_export(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->export(node));
}

/**
 * lasso_node_export_to_base64:
 * @node: a LassoNode
 * 
 * Like lasso_node_export() method except that result is Base64 encoded.
 * 
 * Return value: a Base64 encoded export of the LassoNode
 **/
xmlChar *
lasso_node_export_to_base64(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->export_to_base64(node));
}

/**
 * lasso_node_export_to_query:
 * @node: a LassoNode
 * @sign_method: the Signature transform method
 * @private_key_file: a private key (may be NULL)
 * 
 * URL-encodes and signes the LassoNode.
 * If private_key_file is NULL, query won't be signed.
 * 
 * Return value: URL-encoded and signed LassoNode
 **/
gchar *
lasso_node_export_to_query(LassoNode            *node,
			   lassoSignatureMethod  sign_method,
			   const gchar          *private_key_file)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->export_to_query(node, sign_method, private_key_file));
}

/**
 * lasso_node_export_to_soap:
 * @node: a LassoNode
 * 
 * Like lasso_node_export() method except that result is SOAP enveloped.
 * 
 * Return value: a SOAP enveloped export of the LassoNode
 **/
xmlChar *
lasso_node_export_to_soap(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->export_to_soap(node));
}

/**
 * lasso_node_get_attr:
 * @node: a LassoNode
 * @name: the attribute name
 * @err: return location for an allocated GError, or NULL to ignore errors
 * 
 * Gets an attribute associated with the node.
 * 
 * Return value: the attribute or NULL if not found.
 **/
LassoAttr *
lasso_node_get_attr(LassoNode      *node,
		    const xmlChar  *name,
		    GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_attr(node, name, err));
}

/**
 * lasso_node_get_attr_value:
 * @node: a LassoNode
 * @name: the attribute name
 * @err: return location for an allocated GError, or NULL to ignore errors
 * 
 * Gets the value of an attribute associated to a node.
 * 
 * Return value: the attribute value or NULL if not found. It's up to the caller
 * to free the memory with xmlFree().
 **/
xmlChar *
lasso_node_get_attr_value(LassoNode      *node,
			  const xmlChar  *name,
			  GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_attr_value(node, name, err));
}

/**
 * lasso_node_get_attrs:
 * @node: a LassoNode
 * 
 * Gets attributes associated with the node.
 * 
 * Return value: an array of attributes or NULL if no attribute found. 
 **/
GPtrArray *
lasso_node_get_attrs(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_attrs(node));
}

/**
 * lasso_node_get_child:
 * @node: a LassoNode
 * @name: the child name
 * @href: the namespace (may be NULL)
 * @err: return location for an allocated GError, or NULL to ignore errors
 * 
 * Gets child of node having given @name and namespace @href.
 * 
 * Return value: a child node
 **/
LassoNode *
lasso_node_get_child(LassoNode      *node,
		     const xmlChar  *name,
		     const xmlChar  *href,
		     GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_child(node, name, href, err));
}

/**
 * lasso_node_get_child_content:
 * @node: a LassoNode
 * @name: the child name
 * @href: the namespace (may be NULL)
 * @err: return location for an allocated GError, or NULL to ignore errors
 * 
 * Gets child content of node having given @name and namespace @href.
 * 
 * Return value: a new xmlChar * or NULL if no child found or no content is
 * available. It's up to the caller to free the memory with xmlFree().
 **/
xmlChar *
lasso_node_get_child_content(LassoNode      *node,
			     const xmlChar  *name,
			     const xmlChar  *href,
			     GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_child_content(node, name, href, err));
}

/**
 * lasso_node_get_children:
 * @node: a LassoNode
 * 
 * Gets direct children of node.
 * 
 * Return value: an array of node or NULL if no children found.
 **/
GPtrArray *
lasso_node_get_children(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_children(node));
}

/**
 * lasso_node_get_content:
 * @node: a LassoNode
 * @err: return location for an allocated GError, or NULL to ignore errors
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
lasso_node_get_content(LassoNode  *node,
		       GError    **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_content(node, err));
}

/**
 * lasso_node_get_name:
 * @node: a LassoNode
 * 
 * Gets the name of the node.
 * 
 * Return value: the name of the node
 **/
xmlChar *
lasso_node_get_name(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_name(node));
}

/**
 * lasso_node_import:
 * @node: a LassoNode
 * @buffer: an XML buffer
 * 
 * Parses the XML buffer and loads it into the node.
 **/
void
lasso_node_import(LassoNode     *node,
		  const xmlChar *buffer)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->import(node, buffer);
}

/**
 * lasso_node_import_from_node:
 * @node: a LassoNode
 * @imported_node: a LassoNode
 * 
 * Put a copy of node->private->node into imported_node->private->node
 **/
void
lasso_node_import_from_node(LassoNode *node,
			    LassoNode *imported_node)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->import_from_node(node, imported_node);
}

/**
 * lasso_node_rename_prop:
 * @node: a LassoNode
 * @old_name: the attribute name
 * @new_name: the new attribute name
 * 
 * Renames an attribute of the node.
 **/
void
lasso_node_rename_prop(LassoNode     *node,
		       const xmlChar *old_name,
		       const xmlChar *new_name)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->rename_prop(node, old_name, new_name);
}

/**
 * lasso_node_verify_signature:
 * @node: a LassoNode
 * @certificate_file: a certificate
 * @err: return location for an allocated GError, or NULL to ignore errors
 * 
 * Verifys the node signature.
 * 
 * Return value: 1 if signature is valid, 0 if invalid. -1 if an error occurs.
 **/
gint
lasso_node_verify_signature(LassoNode    *node,
			    const gchar  *certificate_file,
			    GError      **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), -1);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->verify_signature(node, certificate_file, err));
}

/*****************************************************************************/
/* virtual private methods                                                   */
/*****************************************************************************/

static void
lasso_node_add_child(LassoNode *node,
		     LassoNode *child,
		     gboolean   unbounded)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(node, child, unbounded);
}

static gint
lasso_node_add_signature(LassoNode      *node,
			 gint            sign_method,
			 const xmlChar  *private_key_file,
			 const xmlChar  *certificate_file,
			 GError        **err)
{
  g_return_val_if_fail(LASSO_IS_NODE(node), -1);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->add_signature(node, sign_method, private_key_file,
			       certificate_file, err));
}

static gchar *
lasso_node_build_query(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->build_query(node));
}

static xmlNodePtr
lasso_node_get_xmlNode(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->get_xmlNode(node));
}

/**
 * lasso_node_new_child:
 * @node: a LassoNode
 * @name: the name of the child
 * @content: the content of the child
 * @unbounded: if TRUE, several children with the same name can be added else
 * the child must be unique.
 * 
 * Add a new child in node.
 * This is an internal function and should not be called by application
 * directly.
 **/
static void
lasso_node_new_child(LassoNode     *node,
		     const xmlChar *name,
		     const xmlChar *content,
		     gboolean       unbounded)
{
  g_return_if_fail(LASSO_IS_NODE(node)); 

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(node, name, content, unbounded);
}

static GData *
lasso_node_serialize(LassoNode *node,
		     GData     *gd)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->serialize(node, gd));
}

static void
lasso_node_set_name(LassoNode     *node,
		    const xmlChar *name)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_name(node, name);
}

static void
lasso_node_set_ns(LassoNode     *node,
		  const xmlChar *href,
		  const xmlChar *prefix)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_ns(node, href, prefix);
}

static void
lasso_node_set_prop(LassoNode     *node,
		    const xmlChar *name,
		    const xmlChar *value)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(node, name, value);
}

static void
lasso_node_set_xmlNode(LassoNode *node,
		       xmlNodePtr libxml_node)
{
  g_return_if_fail(LASSO_IS_NODE(node));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_xmlNode(node, libxml_node);
}

/*****************************************************************************/
/* implementation methods                                                    */
/*****************************************************************************/

static LassoNode *
lasso_node_impl_copy(LassoNode *node)
{
  LassoNode *copy;
  
  copy = LASSO_NODE(g_object_new(G_OBJECT_TYPE(node), NULL));
  lasso_node_set_xmlNode(copy, xmlCopyNode(node->private->node, 1));

  return (copy);
}

static void
lasso_node_impl_destroy(LassoNode *node)
{
  g_object_unref(G_OBJECT(node));
}

static xmlChar *
lasso_node_impl_dump(LassoNode     *node,
		     const xmlChar *encoding,
		     int            format)
{
  xmlChar *ret;
  xmlOutputBufferPtr buf;
  xmlCharEncodingHandlerPtr handler = NULL;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  /* encoding is optional */
  g_return_val_if_fail (format == 0 || format == 1, NULL);

  if (encoding != NULL) {
    handler = xmlFindCharEncodingHandler(encoding);
    if (handler == NULL) {
      return (NULL);
    }
  }
  buf = xmlAllocOutputBuffer(handler);
  if (buf == NULL) {
    return (NULL);
  }
  xmlNodeDumpOutput(buf, NULL, node->private->node,
		    0, format, encoding);
  xmlOutputBufferFlush(buf);
  if (buf->conv != NULL) {
    /* ret = g_strdup(buf->conv->content); */
    ret = buf->conv->content;
    buf->conv->content = NULL;
  }
  else {
    /* ret = g_strdup(buf->buffer->content); */
    ret = buf->buffer->content;
    buf->buffer->content = NULL;
  }
  xmlOutputBufferClose(buf);

  return (ret);
}

static xmlChar *
lasso_node_impl_export(LassoNode *node)
{
  /* using lasso_node_impl_dump because dump method can be overrided */
  return (lasso_node_impl_dump(node, "utf-8", 0));
}

static xmlChar *
lasso_node_impl_export_to_base64(LassoNode *node)
{
  xmlChar *buffer, *ret;

  buffer = lasso_node_impl_dump(node, "utf-8", 0);
  ret = xmlSecBase64Encode((const xmlSecByte *) buffer,
			   (xmlSecSize)strlen((const char *)buffer), 0);
  g_free(buffer);

  return (ret);
}

static gchar *
lasso_node_impl_export_to_query(LassoNode            *node,
				lassoSignatureMethod  sign_method,
				const gchar          *private_key_file)
{
  GString *query;
  xmlDocPtr doc;
  xmlChar *str1, *str2, *str_escaped = NULL;
  gchar *unsigned_query, *ret;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  unsigned_query = lasso_node_build_query(node);
  query = g_string_new(unsigned_query);
  g_free(unsigned_query);
  
  if (sign_method > 0 && private_key_file != NULL) {
    /* add SigAlg in query */
    query = g_string_append(query, "&SigAlg=");
    switch (sign_method) {
    case lassoSignatureMethodRsaSha1:
      str_escaped = lasso_str_escape((xmlChar *)xmlSecHrefRsaSha1);
      break;
    case lassoSignatureMethodDsaSha1:
      str_escaped = lasso_str_escape((xmlChar *)xmlSecHrefDsaSha1);
      break;
    }
    query = g_string_append(query, str_escaped);
    xmlFree(str_escaped);

    /* try to sign query */
    doc = lasso_str_sign(query->str, sign_method, private_key_file);
    if (doc != NULL) {
      str1 = lasso_doc_get_node_content(doc, xmlSecNodeSignatureValue);
      str2 = lasso_str_escape(str1);
      xmlFree(str1);
      xmlFreeDoc(doc);
    }
    else {
      g_string_free(query, TRUE);
      return (NULL);
    }

    /* add signature in query */
    query = g_string_append(query, "&Signature=");
    query = g_string_append(query, str2);
    xmlFree(str2);
  }

  ret = g_strdup(query->str);
  g_string_free(query, TRUE);
  return (ret);
}

/**
 * lasso_node_impl_export_to_soap:
 * @node: a LassoNode
 * 
 * 
 * 
 * Return value: 
 **/
static xmlChar *
lasso_node_impl_export_to_soap(LassoNode *node)
{
  LassoNode *envelope, *body, *copy_node;
  xmlChar *buffer;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  
  envelope = lasso_node_new();
  lasso_node_set_name(envelope, "Envelope");
  lasso_node_set_ns(envelope, lassoSoapEnvHRef, lassoSoapEnvPrefix);

  copy_node = lasso_node_copy(node);
  
  body = lasso_node_new();
  lasso_node_set_name(body, "Body");
  lasso_node_set_ns(body, lassoSoapEnvHRef, lassoSoapEnvPrefix);
  
  lasso_node_add_child(body, copy_node, FALSE);
  lasso_node_add_child(envelope, body, FALSE);

  buffer = lasso_node_export(envelope);

  lasso_node_destroy(copy_node);
  lasso_node_destroy(body);
  lasso_node_destroy(envelope);
  
  return(buffer);
}

static LassoAttr*
lasso_node_impl_get_attr(LassoNode      *node,
			 const xmlChar  *name,
			 GError        **err)
{
  LassoAttr *prop;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  prop = node->private->node->properties;
  while (prop != NULL) {
    if (xmlStrEqual(prop->name, name)) {
      return (prop);
    }
    prop = prop->next;
  }

  /* attr not found */
  g_set_error(err, g_quark_from_string("Lasso"),
	      LASSO_XML_ERROR_ATTR_NOTFOUND,
	      lasso_strerror(LASSO_XML_ERROR_ATTR_NOTFOUND),
	      name, node->private->node->name);
  return (NULL);
}

static xmlChar *
lasso_node_impl_get_attr_value(LassoNode      *node,
			       const xmlChar  *name,
			       GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  xmlChar *value = xmlGetProp(node->private->node, name);

  if (value == NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_XML_ERROR_ATTR_VALUE_NOTFOUND,
		lasso_strerror(LASSO_XML_ERROR_ATTR_VALUE_NOTFOUND),
		name, node->private->node->name);
  }

  return (value);
}

static GPtrArray *
lasso_node_impl_get_attrs(LassoNode *node)
{
  GPtrArray *attributes = NULL;
  LassoAttr *prop;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  prop = node->private->node->properties;
  if (prop != NULL)
    attributes = g_ptr_array_new();

  while (prop != NULL) {
    g_ptr_array_add(attributes, prop);
    prop = prop->next;
  }

  return (attributes);
}

static LassoNode *
lasso_node_impl_get_child(LassoNode      *node,
			  const xmlChar  *name,
			  const xmlChar  *href,
			  GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  /*   /\* No recurssive version *\/ */
  /*   xmlNodePtr cur; */
  
  /*   cur = node->private->node->children; */
  /*   while (cur != NULL) { */
  /*     if(cur->type == XML_ELEMENT_NODE) { */
  /*       if (xmlStrEqual(cur->name, name)) { */
  /*   	return (lasso_node_new_from_xmlNode(cur)); */
  /*       } */
  /*     } */
  /*     cur = cur->next; */
  /*   } */
  /*   return (NULL); */

  /*   /\* Recurssive version *\/ */
  /*   xmlNodePtr cur; */
  /*   LassoNode *ret, *child; */
  
  /*   cur = node->private->node; */
  /*   while (cur != NULL) { */
  /*     if ((cur->type == XML_ELEMENT_NODE) && xmlStrEqual(cur->name, name)) { */
  /*       return (lasso_node_new_from_xmlNode(cur)); */
  /*     } */
  /*     if (cur->children != NULL) { */
  /*       child = lasso_node_new_from_xmlNode(cur->children); */
  /*       ret = lasso_node_get_child(child, name); */
  /*       if (ret != NULL) { */
  /* 	return (ret); */
  /*       } */
  /*     } */
  /*     cur = cur->next; */
  /*   } */
  /*   return (NULL); */

  xmlNodePtr child;

  if (href != NULL) {
    child = xmlSecFindNode(node->private->node, name, href);
  }
  else {
    child = xmlSecFindNode(node->private->node, name, href);
    if (child == NULL)
      child = xmlSecFindNode(node->private->node, name, lassoLibHRef);
    if (child == NULL)
      child = xmlSecFindNode(node->private->node, name, lassoSamlAssertionHRef);
    if (child == NULL)
      child = xmlSecFindNode(node->private->node, name, lassoSamlProtocolHRef);
    if (child == NULL)
      child = xmlSecFindNode(node->private->node, name, lassoSoapEnvHRef);
    if (child == NULL)
      child = xmlSecFindNode(node->private->node, name, lassoMetadataHRef);
    if (child == NULL)
      child = xmlSecFindNode(node->private->node, name, lassoLassoHRef);
  }
  if (child != NULL) {
    return (lasso_node_new_from_xmlNode(child));
  }
  else {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_XML_ERROR_NODE_NOTFOUND,
		lasso_strerror(LASSO_XML_ERROR_NODE_NOTFOUND),
		name, node->private->node->name);
    return (NULL);
  }
}

static xmlChar *
lasso_node_impl_get_child_content(LassoNode      *node,
				  const xmlChar  *name,
				  const xmlChar  *href,
				  GError        **err)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  GError    *tmp_err = NULL;
  LassoNode *child = lasso_node_get_child(node, name, href, &tmp_err);
  xmlChar   *content = NULL;

  if (child != NULL) {
    content = lasso_node_get_content(child, &tmp_err);
    lasso_node_destroy(child);
    if (content == NULL) {
      g_propagate_error (err, tmp_err);
    }
  }
  else {
    g_propagate_error (err, tmp_err);
  }

  return (content);
}

static GPtrArray *
lasso_node_impl_get_children(LassoNode *node)
{
  GPtrArray *children = NULL;
  xmlNodePtr cur;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  cur = node->private->node->children;
  if (cur != NULL)
    children = g_ptr_array_new();
  
  while (cur != NULL) {
    g_ptr_array_add(children, lasso_node_new_from_xmlNode(cur));
    cur = cur->next;
  }

  return (children);
}

static xmlChar *
lasso_node_impl_get_content(LassoNode  *node,
			    GError    **err)
{
  xmlChar *content;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
  g_return_val_if_fail (err == NULL || *err == NULL, NULL);

  content = xmlNodeGetContent(node->private->node);
  if (content == NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_XML_ERROR_NODE_CONTENT_NOTFOUND,
		lasso_strerror(LASSO_XML_ERROR_NODE_CONTENT_NOTFOUND),
		node->private->node->name);
  }

  return (content);
}

static xmlChar *
lasso_node_impl_get_name(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  return (xmlStrdup(node->private->node->name));
}

static void
lasso_node_impl_import(LassoNode     *node,
		       const xmlChar *buffer)
{
  xmlDocPtr doc;
  xmlNodePtr root;

  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (buffer != NULL);

  doc = xmlParseMemory(buffer, strlen(buffer));
  /* get root element of doc and duplicate it */
  root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
  lasso_node_set_xmlNode(node, root);
  /* free doc */
  xmlFreeDoc(doc);
}

static void
lasso_node_impl_import_from_node(LassoNode *node,
				 LassoNode *imported_node)
{
  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (LASSO_IS_NODE(imported_node));

  lasso_node_impl_set_xmlNode(node, xmlCopyNode(imported_node->private->node, 1));
}

static void
lasso_node_impl_rename_prop(LassoNode     *node,
			    const xmlChar *old_name,
			    const xmlChar *new_name)
{
  xmlChar *value;

  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (old_name != NULL);
  g_return_if_fail (new_name != NULL);

  value = xmlGetProp(node->private->node, old_name);
  if (value != NULL) {
    xmlRemoveProp(lasso_node_get_attr(node, old_name, NULL));
    lasso_node_set_prop(node, new_name, value);
  }
}

static gint
lasso_node_impl_verify_signature(LassoNode    *node,
				 const gchar  *certificate_file,
				 GError      **err)
{
  xmlDocPtr doc = xmlNewDoc("1.0");
  xmlNodePtr xmlNode_copy = NULL;
  xmlNodePtr signature = NULL;
  xmlSecKeysMngrPtr mngr = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  gint ret = 0;

  g_return_val_if_fail (LASSO_IS_NODE(node), LASSO_PARAM_ERROR_INVALID_OBJ_TYPE);
  g_return_val_if_fail (certificate_file != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  /* create a copy of the xmlNode (node->private->node) of @node */
  xmlNode_copy = xmlCopyNode(lasso_node_get_xmlNode(node), 1);

  /* we must associate the xmlNode with an xmlDoc !!! */
  xmlAddChild((xmlNodePtr)doc, xmlNode_copy);

  /* find start node */
  signature = xmlSecFindNode(xmlNode_copy, xmlSecNodeSignature, 
			     xmlSecDSigNs);
  if (signature == NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_SIGNATURE_NOTFOUND,
		lasso_strerror(LASSO_DS_ERROR_SIGNATURE_NOTFOUND));
    ret = LASSO_DS_ERROR_SIGNATURE_NOTFOUND;
    goto done;	
  }

  /* create simple keys mngr */
  mngr = xmlSecKeysMngrCreate();
  if (mngr == NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED,
		lasso_strerror(LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED));
    ret = LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED;
    goto done;
  }

  if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED,
		lasso_strerror(LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED));
    ret = LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED;
    goto done;
  }
  
  /* load trusted cert */
  if (xmlSecCryptoAppKeysMngrCertLoad(mngr, certificate_file,
				      xmlSecKeyDataFormatPem,
				      xmlSecKeyDataTypeTrusted) < 0) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED,
		lasso_strerror(LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED),
		certificate_file);
    ret = LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED;
    goto done;
  }

  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  if (dsigCtx == NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_CONTEXT_CREATION_FAILED,
		lasso_strerror(LASSO_DS_ERROR_CONTEXT_CREATION_FAILED));
    ret = LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
    goto done;
  }

  /* verify signature */
  if (xmlSecDSigCtxVerify(dsigCtx, signature) < 0) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED,
		lasso_strerror(LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED));
    ret = LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
    goto done;
  }

  if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
    ret = 0;
  }
  else {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_DS_ERROR_INVALID_SIGNATURE,
		lasso_strerror(LASSO_DS_ERROR_INVALID_SIGNATURE),
		node->private->node->name);
    ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
  }

 done:
  /* cleanup */
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  if(mngr != NULL) {
    xmlSecKeysMngrDestroy(mngr);
  }
  xmlFreeDoc(doc);
  return (ret);
}

/*** private methods **********************************************************/

static void
lasso_node_impl_add_child(LassoNode *node,
			  LassoNode *child,
			  gboolean   unbounded)
{
  xmlNodePtr old_child = NULL;
  const xmlChar *href = NULL;

  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (LASSO_IS_NODE(child));

  /* if child is not unbounded, we search it */
  if (!unbounded) {
    if (node->private->node->ns != NULL) {
      href = node->private->node->ns->href;
    }
    old_child = xmlSecFindNode(node->private->node,
			       child->private->node->name,
			       href);
  }

  if (!unbounded && old_child != NULL) {
    /* child replace old child */
    xmlReplaceNode(old_child, child->private->node);
  }
  else {
    /* else child is added */
    xmlAddChild(node->private->node, child->private->node);
  }
  child->private->node_is_weak_ref = TRUE;
}

static gint
lasso_node_impl_add_signature(LassoNode      *node,
			      gint            sign_method,
			      const xmlChar  *private_key_file,
			      const xmlChar  *certificate_file,
			      GError        **err)
{
  LassoNode *signature = NULL;
  gint ret = 0;
  GError *tmp_err = NULL;

  g_return_val_if_fail (err == NULL || *err == NULL, LASSO_ERR_ERROR_CHECK_FAILED);

  switch (sign_method) {
  case lassoSignatureMethodRsaSha1:
    signature = lasso_ds_signature_new(node, xmlSecTransformRsaSha1Id);
    break;
  case lassoSignatureMethodDsaSha1:
    signature = lasso_ds_signature_new(node, xmlSecTransformDsaSha1Id);
    break;
  }
  lasso_node_add_child(node, signature, TRUE);
  ret = lasso_ds_signature_sign(LASSO_DS_SIGNATURE(signature),
				private_key_file,
				certificate_file,
				&tmp_err);
  lasso_node_destroy(signature);
  if (ret < 0) {
    ret = tmp_err->code;
    g_propagate_error(err, tmp_err);
  }

  return (ret);
}

static void gdata_build_query_foreach_func(GQuark   key_id,
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
  }
  g_ptr_array_add(array, g_strdup((gpointer)g_quark_to_string(key_id)));
  g_ptr_array_add(array, str->str);
  g_string_free(str, FALSE);
  g_ptr_array_add((GPtrArray *)user_data, array);
}

static gchar *
lasso_node_impl_build_query(LassoNode *node)
{
  guint i, j;
  GData *gd;
  GPtrArray *a, *aa;
  GString *query;
  xmlChar *str_escaped;
  gchar   *ret;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

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
    str_escaped = lasso_str_escape(g_ptr_array_index(aa, 1));
    query = g_string_append(query, str_escaped);
    xmlFree(str_escaped);
    if (i<a->len - 1) {
      query = g_string_append(query, "&");
    }
    /* free allocated memory for array aa */
    for (j=0; j<aa->len; j++) {
      g_free(aa->pdata[j]);
    }
    g_ptr_array_free(aa, TRUE);
  }
  /* free allocated memory for array a */
  g_ptr_array_free(a, TRUE);
  g_datalist_clear(&gd);

  ret = g_strdup(query->str);
  g_string_free(query, TRUE);
  
  return (ret);
}

static xmlNodePtr
lasso_node_impl_get_xmlNode(LassoNode *node)
{
  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  return (node->private->node);
}

static void
lasso_node_impl_new_child(LassoNode     *node,
			  const xmlChar *name,
			  const xmlChar *content,
			  gboolean       unbounded)
{
  /* LassoNode *old_child = NULL; */
  xmlNodePtr old_child = NULL;
  const xmlChar *href = NULL;

  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (name != NULL);
  g_return_if_fail (content != NULL);
  
  if (!unbounded) {
    if (node->private->node->ns != NULL) {
      href = node->private->node->ns->href;
    }
    old_child = xmlSecFindNode(node->private->node, name, href);
    /* old_child = lasso_node_get_child(node, name); */
  }

  if (!unbounded && old_child != NULL) {
    /* xmlNodeSetContent(old_child->private->node, content); */
    xmlNodeSetContent(old_child, content);
  }
  else {
    xmlNewTextChild(node->private->node, NULL, name, content);
  }
}

static void
gdata_serialize_destroy_notify(gpointer data)
{
  gint i;
  GPtrArray *array = data;

  for (i=0; i<array->len; i++) {
    xmlFree(array->pdata[i]);
  }
  g_ptr_array_free(array, TRUE);
}

static GData *
lasso_node_impl_serialize(LassoNode *node,
			  GData     *gd)
{
  GPtrArray *attrs, *children;
  GPtrArray *values;
  xmlChar *name;
  xmlChar *val;
  int i;

  g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

  if (gd == NULL) {
    g_datalist_init(&gd);
  }

  attrs = lasso_node_get_attrs(node);
  if (attrs != NULL) {
    for(i=0; i<attrs->len; i++) {
      values = g_ptr_array_new();
      name = (xmlChar *)((LassoAttr *)g_ptr_array_index(attrs, i))->name;
      /* xmlGetProp returns a COPY of attr value
	 each val must be xmlFree in gdata_serialize_destroy_notify()
	 which is called by g_datalist_clear() */
      val = xmlGetProp(node->private->node, name);
      g_ptr_array_add(values, val);
      g_datalist_set_data_full(&gd, name, values, gdata_serialize_destroy_notify);
    }
    g_ptr_array_free(attrs, TRUE);
  }

  children = lasso_node_get_children(node);
  if (children != NULL) {
    for(i=0; i<children->len; i++) {
      xmlNodePtr xml_node = ((LassoNode *)g_ptr_array_index(children, i))->private->node;
      switch (xml_node->type) {
      case XML_ELEMENT_NODE:
	gd = lasso_node_serialize(g_ptr_array_index(children, i), gd);
	break;
      case XML_TEXT_NODE:
	name = lasso_node_get_name(node);
	/* xmlNodeGetContent returns a COPY of node content
	   each val must be xmlFree in gdata_serialize_destroy_notify()
	   which is called by g_datalist_clear() */
	val = xmlNodeGetContent(node->private->node);
	if (val == NULL) {
	  break;
	}
	values = (GPtrArray *)g_datalist_get_data(&gd, name);
	if (values == NULL) {
	  values = g_ptr_array_new();
	  g_ptr_array_add(values, val);
	  g_datalist_set_data_full(&gd, name, values,
				   gdata_serialize_destroy_notify);
	}
	else {
	  g_ptr_array_add(values, val);
	}
	xmlFree(name);
	break;
      }
      lasso_node_destroy((LassoNode *)g_ptr_array_index(children, i));
    }
    g_ptr_array_free(children, TRUE);
  }
    
  return (gd);
}

static void
lasso_node_impl_set_name(LassoNode     *node,
			 const xmlChar *name)
{
  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (name != NULL);

  xmlNodeSetName(node->private->node, name);
}

static void
lasso_node_impl_set_ns(LassoNode     *node,
		       const xmlChar *href,
		       const xmlChar *prefix)
{
  xmlNsPtr new_ns;

  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (href != NULL || prefix != NULL);

  /*   xmlNsPtr cur; */
  /*   cur = node->private->node->ns; */
  /*   while (cur != NULL) { */
  /*     printf("%s:%s\n", cur->prefix, cur->href); */
  /*     cur = cur->next; */
  /*   } */
  /*   cur = node->private->node->nsDef; */
  /*   while (cur != NULL) { */
  /*     printf("%s:%s\n", cur->prefix, cur->href); */
  /*     cur = cur->next; */
  /*   } */

  new_ns = xmlNewNs(node->private->node, href, prefix);
  xmlFreeNs(node->private->node->ns);
  xmlSetNs(node->private->node, new_ns);
  node->private->node->nsDef = new_ns;
}

static void
lasso_node_impl_set_prop(LassoNode     *node,
			 const xmlChar *name,
			 const xmlChar *value)
{
  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (name != NULL);
  g_return_if_fail (value != NULL);

  xmlSetProp(node->private->node, name, value);
}

static void
lasso_node_impl_set_xmlNode(LassoNode  *node,
			    xmlNodePtr  libxml_node)
{
  g_return_if_fail (LASSO_IS_NODE(node));
  g_return_if_fail (libxml_node != NULL);

  xmlFreeNode(node->private->node);
  node->private->node = libxml_node;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_node_dispose(LassoNode *node)
{
  if (node->private->dispose_has_run == TRUE) {
    return;
  }
  node->private->dispose_has_run = TRUE;

  if (node->private->node->name != NULL) {
    debug("%s 0x%x disposed ...\n", node->private->node->name, node);
  }
  /* unref reference counted objects */
  /* we don't have any here */

  parent_class->dispose(G_OBJECT(node));
}

static void
lasso_node_finalize(LassoNode *node)
{
  if (node->private->node->name != NULL) {
    debug("%s 0x%x finalized ...\n", node->private->node->name, node);
  }

  if (node->private->node_is_weak_ref == FALSE) {
    xmlUnlinkNode(node->private->node);
    xmlFreeNode(node->private->node);
    node->private->node = NULL;
  }

  g_free (node->private);
  node->private = NULL;

  parent_class->finalize(G_OBJECT(node));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_node_instance_init(LassoNode *instance)
{
  LassoNode *node = LASSO_NODE(instance);

  node->private = g_new (LassoNodePrivate, 1);
  node->private->dispose_has_run  = FALSE;
  node->private->node_is_weak_ref = FALSE;
  node->private->node             = xmlNewNode(NULL, "no-name-set");
}

static void
lasso_node_class_init(LassoNodeClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(class);
  
  parent_class = g_type_class_peek_parent(class);
  /* virtual public methods */
  class->copy              = lasso_node_impl_copy;
  class->destroy           = lasso_node_impl_destroy;
  class->dump              = lasso_node_impl_dump;
  class->export            = lasso_node_impl_export;
  class->export_to_base64  = lasso_node_impl_export_to_base64;
  class->export_to_query   = lasso_node_impl_export_to_query;
  class->export_to_soap    = lasso_node_impl_export_to_soap;
  class->get_attr          = lasso_node_impl_get_attr;
  class->get_attr_value    = lasso_node_impl_get_attr_value;
  class->get_attrs         = lasso_node_impl_get_attrs;
  class->get_child         = lasso_node_impl_get_child;
  class->get_child_content = lasso_node_impl_get_child_content;
  class->get_children      = lasso_node_impl_get_children;
  class->get_content       = lasso_node_impl_get_content;
  class->get_name          = lasso_node_impl_get_name;
  class->import            = lasso_node_impl_import;
  class->import_from_node  = lasso_node_impl_import_from_node;
  class->rename_prop       = lasso_node_impl_rename_prop;
  class->verify_signature  = lasso_node_impl_verify_signature;
  /* virtual private methods */
  class->add_child     = lasso_node_impl_add_child;
  class->add_signature = lasso_node_impl_add_signature;
  class->build_query   = lasso_node_impl_build_query;
  class->get_xmlNode   = lasso_node_impl_get_xmlNode;
  class->new_child     = lasso_node_impl_new_child;
  class->serialize     = lasso_node_impl_serialize;
  class->set_name      = lasso_node_impl_set_name;
  class->set_ns        = lasso_node_impl_set_ns;
  class->set_prop      = lasso_node_impl_set_prop;
  class->set_xmlNode   = lasso_node_impl_set_xmlNode;
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

/**
 * lasso_node_new:
 * 
 * The main LassoNode constructor.
 * 
 * Return value: a new node
 **/
LassoNode*
lasso_node_new()
{
  return (LASSO_NODE(g_object_new(LASSO_TYPE_NODE, NULL)));
}

/**
 * lasso_node_new_from_dump:
 * @buffer: a buffer
 * 
 * Builds a new LassoNode from an LassoNode dump.
 * 
 * Return value: a new node
 **/
LassoNode*
lasso_node_new_from_dump(const xmlChar *buffer)
{
  LassoNode *node;
  xmlDocPtr  doc;
  xmlNodePtr root;

  g_return_val_if_fail (buffer != NULL, NULL);

  node = LASSO_NODE(g_object_new(LASSO_TYPE_NODE, NULL));
  doc = xmlParseMemory(buffer, strlen(buffer));
  /* get root element of doc and duplicate it */
  root = xmlCopyNode(xmlDocGetRootElement(doc), 1);
  lasso_node_set_xmlNode(node, root);
  /* free doc */
  xmlFreeDoc(doc);

  return (node);
}

/**
 * lasso_node_new_from_xmlNode:
 * @node: an xmlNode
 * 
 * Builds a new LassoNode from an xmlNode.
 * 
 * Return value: a new node
 **/
LassoNode*
lasso_node_new_from_xmlNode(xmlNodePtr node)
{
  LassoNode *lasso_node;

  g_return_val_if_fail (node != NULL, NULL);

  lasso_node = LASSO_NODE(g_object_new(LASSO_TYPE_NODE, NULL));
  lasso_node_set_xmlNode(lasso_node, node);
  lasso_node->private->node_is_weak_ref = TRUE;

  return (lasso_node);
}
