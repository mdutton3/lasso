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

#include <ctype.h>

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/base64.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/xml/xml.h>
#include <lasso/xml/saml_name_identifier.h>


static void lasso_node_build_xmlNode_from_snippets(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippets, gboolean lasso_dump);
static struct XmlSnippet* find_xml_snippet_by_name(LassoNode *node, char *name);
static int set_value_at_path(LassoNode *node, char *path, char *query_value);
static char* get_value_by_path(LassoNode *node, char *path, struct XmlSnippet *xml_snippet);
static int find_path(LassoNode *node, char *path, LassoNode **value_node,
		struct XmlSnippet **snippet);

static
void lasso_node_add_signature_template(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippet_signature);

static void xmlCleanNs(xmlNode *root_node);

/*****************************************************************************/
/* virtual public methods                                                    */
/*****************************************************************************/

/**
 * lasso_node_dump:
 * @node: a #LassoNode
 * @encoding: the name of character set encoding to use or NULL for default
 *      (UTF-8).
 * @format: whether formatting is allowed
 * 
 * Dumps @node.  All datas in object are dumped in an XML format.
 * 
 * Return value: a full XML dump of @node.  The string must be freed by the
 *     caller.
 **/
char*
lasso_node_dump(LassoNode *node, const char *encoding, int format)
{
	xmlNode *xmlnode;
	char *ret;
	xmlOutputBufferPtr buf;
	xmlCharEncodingHandlerPtr handler = NULL;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
	/* encoding is optional */
	g_return_val_if_fail (format == 0 || format == 1, NULL);

	if (encoding != NULL) {
		handler = xmlFindCharEncodingHandler(encoding);
		if (handler == NULL) {
			return NULL;
		}
	}
	buf = xmlAllocOutputBuffer(handler);
	if (buf == NULL) {
		return NULL;
	}
	xmlnode = lasso_node_get_xmlNode(node, TRUE);
	xmlNodeDumpOutput(buf, NULL, xmlnode, 0, format, encoding);
	xmlOutputBufferFlush(buf);
	if (buf->conv != NULL) {
		ret = g_strdup(buf->conv->content);
	}
	else {
		ret = g_strdup(buf->buffer->content);
	}
	xmlOutputBufferClose(buf);

	xmlFreeNode(xmlnode);

	return ret;

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
		message(G_LOG_LEVEL_CRITICAL, "lasso_node_destroy of NULL!!!");
		return;
	}
	if (LASSO_IS_NODE(node)) {
		LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
		class->destroy(node);
	}
}

static xmlNode*
lasso_node_export_to_signed_xmlnode(LassoNode *node,
		const char *private_key_file, const char *certificate_file)
{
	xmlNode *message;
	char *id_attr_name = NULL, *id_value = NULL;

	message = lasso_node_get_xmlNode(node, FALSE);

	if (private_key_file) {
		int rc;

		if (LASSO_NODE_GET_CLASS(node)->get_sign_attr_name) {
			id_attr_name = LASSO_NODE_GET_CLASS(node)->get_sign_attr_name();
			id_value = xmlGetProp(message, id_attr_name);
		}

		rc = lasso_sign_node(message, id_attr_name, id_value,
				private_key_file, certificate_file);
		/* it may have failed; should we care and return NULL or let
		 * the unsigned message go on the wire ? */
		if (id_value)
			xmlFree(id_value);
	}

	return message;
}


/**
 * lasso_node_export_to_base64:
 * @node: a #LassoNode
 * @private_key_file: the path to the private key for signature (may be NULL)
 * @certificate_file: the path to the certificate for signature (may be NULL)
 * 
 * Exports @node to a base64-encoded message.
 * 
 * Return value: a base64-encoded export of @node.  The string must be freed by
 *      the caller.
 **/
char*
lasso_node_export_to_base64(LassoNode *node,
		const char *private_key_file, const char *certificate_file)
{
	xmlNode *message;
	xmlOutputBufferPtr buf;
	xmlCharEncodingHandlerPtr handler = NULL;
	char *buffer;
	char *ret;

	message = lasso_node_export_to_signed_xmlnode(node, private_key_file, certificate_file);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, message, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	buffer = buf->conv ? buf->conv->content : buf->buffer->content;

	ret = xmlSecBase64Encode(buffer, strlen(buffer), 0);
	xmlOutputBufferClose(buf);

	return ret;
}

/**
 * lasso_node_export_to_query:
 * @node: a #LassoNode
 * @sign_method: the Signature transform method
 * @private_key_file: the path to the private key (may be NULL)
 * 
 * Exports @node to a HTTP query string.  If @private_key_file is NULL,
 * query won't be signed.
 * 
 * Return value: a HTTP query export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_query(LassoNode *node,
		lassoSignatureMethod sign_method, const char *private_key_file)
{
	char *unsigned_query, *query;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

	unsigned_query = lasso_node_build_query(node);
	if (private_key_file)
		query = lasso_query_sign(unsigned_query, sign_method, private_key_file);
	else
		query = g_strdup(unsigned_query);
	g_free(unsigned_query);

	return query;
}

/**
 * lasso_node_export_to_soap:
 * @node: a #LassoNode
 * @private_key_file: the path to the private key for signature (may be NULL)
 * @certificate_file: the path to the certificate for signature (may be NULL)
 * 
 * Exports @node to a SOAP message.
 * 
 * Return value: a SOAP export of @node.  The string must be freed by the
 *      caller.
 **/
char*
lasso_node_export_to_soap(LassoNode *node,
		const char *private_key_file, const char *certificate_file)
{
	xmlNode *envelope, *body, *message;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	char *ret;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

	message = lasso_node_export_to_signed_xmlnode(node, private_key_file, certificate_file);

	envelope = xmlNewNode(NULL, "Envelope");
	xmlSetNs(envelope, xmlNewNs(envelope, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX));

	body = xmlNewTextChild(envelope, NULL, "Body", NULL);
	xmlAddChild(body, message);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, envelope, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	ret = g_strdup( buf->conv ? buf->conv->content : buf->buffer->content );
	xmlOutputBufferClose(buf);

	xmlFreeNode(envelope);

	return ret;
}


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
	for (i=0; query_fields[i]; i++) {
		free(query_fields[i]);
	}
	free(query_fields);
	return rc;
}

int
lasso_node_init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoNodeClass *class;

	g_return_val_if_fail(LASSO_IS_NODE(node), -1);
	class = LASSO_NODE_GET_CLASS(node);

	return class->init_from_xml(node, xmlnode);
}


/**
 * lasso_node_verify_signature:
 * @node: a #LassoNode
 * @public_key_file: the path to a public key (or a certificate) file
 * @ca_cert_chain_file: the path to the CA certificate chain file
 * 
 * Verifies the node signature of @node.
 * 
 * Return value: 0 if signature is valid; or a positive value if signature was
 *      not found or was invalid; or a negative value if an error occured
 *      during the verification.
 **/
gint
lasso_node_verify_signature(LassoNode *node,
		const char *public_key_file, const char *ca_cert_chain_file)
{
	return 0;
#if 0 /* XXX: signature should be verified when importing request */
	xmlDocPtr doc = NULL;
	xmlNodePtr xmlNode = NULL;
	xmlNodePtr signature = NULL;
	xmlNodePtr x509data = NULL;
	xmlSecKeysMngrPtr keys_mngr = NULL;
	xmlSecDSigCtxPtr dsigCtx = NULL;
	xmlIDPtr id;
	xmlAttrPtr id_attr;
	xmlChar *id_value;
	lassoPemFileType public_key_file_type;
	gint ret = 0;

	doc = xmlNewDoc("1.0");
	/* Don't use xmlCopyNode here because it changes the attrs and ns order :-( */
	xmlNode = lasso_node_get_xmlNode(node);
	xmlAddChild((xmlNodePtr)doc, xmlNode);

	/* FIXME : register 'AssertionID' ID attribute manually */
	id_attr = lasso_node_get_attr(node, "AssertionID", NULL);
	if (id_attr != NULL) {
		id_value = xmlNodeListGetString(doc, id_attr->children, 1);
		id = xmlAddID(NULL, doc, id_value, id_attr);
		xmlFree(id_value);
	}

	/* find start node */
	signature = xmlSecFindNode(xmlNode, xmlSecNodeSignature,
			xmlSecDSigNs);
	if (signature == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_SIGNATURE_NOT_FOUND),
				node->private->node->name);
		ret = LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
		goto done;	
	}

	x509data = xmlSecFindNode(xmlNode, xmlSecNodeX509Data,
			xmlSecDSigNs);
	if (x509data != NULL && ca_cert_chain_file != NULL) {
		/* create a keys manager */
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(ca_cert_chain_file);
		if (keys_mngr == NULL) {
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED));
			ret = LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
			goto done;
		}
	}

	/* create signature context */
	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);
	if (dsigCtx == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_CONTEXT_CREATION_FAILED));
		ret = LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
		goto done;
	}

	if (keys_mngr == NULL) {
		if (public_key_file != NULL) {
			/* auto-detect public_key_file type */
			public_key_file_type = lasso_get_pem_file_type(public_key_file);
			if (public_key_file_type == LASSO_PEM_FILE_TYPE_CERT) {
				/* public_key_file is a certificate file => get public key in it */
				dsigCtx->signKey = lasso_get_public_key_from_pem_cert_file(
						public_key_file);
			}
			else {
				/* load public key */
				dsigCtx->signKey = xmlSecCryptoAppKeyLoad(public_key_file,
						xmlSecKeyDataFormatPem,
						NULL, NULL, NULL);
			}
		}
		if (dsigCtx->signKey == NULL) {
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED),
					public_key_file);
			ret = LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
			goto done;
		}
	}

	/* verify signature */
	if (xmlSecDSigCtxVerify(dsigCtx, signature) < 0) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED),
				node->private->node->name);
		ret = LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
		goto done;
	}

	if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
		ret = 0;
	}
	else {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_INVALID_SIGNATURE),
				node->private->node->name);
		ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
	}

done:
	/* cleanup */
	if(dsigCtx != NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
	}
	if(keys_mngr != NULL) {
		xmlSecKeysMngrDestroy(keys_mngr);
	}
	/* FIXME xmlFreeDoc(doc); */
	return ret;
#endif
}

/*****************************************************************************/
/* virtual private methods                                                   */
/*****************************************************************************/

char*
lasso_node_build_query(LassoNode *node)
{
	LassoNodeClass *class;
	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

	class = LASSO_NODE_GET_CLASS(node);
	return class->build_query(node);
}

xmlNodePtr
lasso_node_get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoNodeClass *class;
	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
	class = LASSO_NODE_GET_CLASS(node);
	return class->get_xmlNode(node, lasso_dump);
}

/*****************************************************************************/
/* implementation methods                                                    */
/*****************************************************************************/

static void
lasso_node_impl_destroy(LassoNode *node)
{
	g_object_unref(G_OBJECT(node));
}

static int
lasso_node_impl_init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	struct XmlSnippet *snippet;
	xmlNode *t;
	LassoNodeClass *class;
	void *value;
	SnippetType type;

	class = LASSO_NODE_GET_CLASS(node);

	if (class->node_data == NULL)
		return 0;

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		
		for (t = xmlnode->children; t; t = t->next) {
			if (t->type != XML_ELEMENT_NODE)
				continue;

			for (snippet = class->node_data->snippets;
					snippet && snippet->name; snippet++) {
				void *tmp = NULL;
				type = snippet->type & 0xff;
				value = G_STRUCT_MEMBER_P(node, snippet->offset);

				if (strcmp(t->name, snippet->name) != 0)
					continue;

				if (type == SNIPPET_NODE) {
					tmp = lasso_node_new_from_xmlNode(t);
				} else if (type == SNIPPET_NODE_IN_CHILD) {
					xmlNode *t2 = t->children;
					while (t2 && t2->type != XML_ELEMENT_NODE)
						t2 = t2->next;
					if (t2)
						tmp = lasso_node_new_from_xmlNode(t2);
				} else if (type == SNIPPET_CONTENT)
					tmp = xmlNodeGetContent(t);
				else if (type == SNIPPET_NAME_IDENTIFIER)
					tmp = lasso_saml_name_identifier_new_from_xmlNode(t);
				else if (type == SNIPPET_LIST_NODES) {
					GList **location = value;
					LassoNode *n = lasso_node_new_from_xmlNode(t);
					*location = g_list_append(*location, n);
				} else if (type == SNIPPET_LIST_CONTENT) {
					GList **location = value;
					xmlChar *s = xmlNodeGetContent(t);
					*location = g_list_append(*location, s);
				} else if (type == SNIPPET_EXTENSION) {
					GList **location = value;
					*location = g_list_append(*location, xmlCopyNode(t, 1));
				}

				if (tmp == NULL)
					break;

				if (snippet->type & SNIPPET_INTEGER) {
					int val = atoi(tmp);
					(*(int*)value) = val;
					xmlFree(tmp);
				} else if (snippet->type & SNIPPET_BOOLEAN) {
					int val = (strcmp((char*)tmp, "true") == 0);
					(*(int*)value) = val;
					xmlFree(tmp);
				} else {
					(*(void**)value) = tmp;
				}

				break;
			}
		}

		for (snippet = class->node_data->snippets; snippet && snippet->name; snippet++) {
			void *tmp = NULL;
			type = snippet->type & 0xff;
			value = G_STRUCT_MEMBER_P(node, snippet->offset);
			if (type == SNIPPET_ATTRIBUTE)
				tmp = xmlGetProp(xmlnode, snippet->name);
			if (type == SNIPPET_TEXT_CHILD)
				tmp = xmlNodeGetContent(xmlnode);
			if (tmp == NULL)
				continue;

			if (snippet->type & SNIPPET_INTEGER) {
				int val = atoi(tmp);
				(*(int*)value) = val;
				xmlFree(tmp);
			} else if (snippet->type & SNIPPET_BOOLEAN) {
				int val = (strcmp((char*)tmp, "true") == 0);
				(*(int*)value) = val;
				xmlFree(tmp);
			} else {
				(*(char**)value) = tmp;
			}

		}

		class = g_type_class_peek_parent(class);
	}
	return 0;
}

/*** private methods **********************************************************/

static char*
lasso_node_impl_build_query(LassoNode *node)
{
	g_assert_not_reached();
	return NULL;
}

static xmlNode*
lasso_node_impl_get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
	xmlNode *xmlnode;
	xmlNs *ns;
	GList *list_ns = NULL, *list_classes = NULL, *t;

	if (class->node_data == NULL)
		return NULL;

	xmlnode = xmlNewNode(NULL, class->node_data->node_name);
	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		if (class->node_data->ns)
			list_ns = g_list_append(list_ns, class->node_data->ns);
		list_classes = g_list_append(list_classes, class);
		class = g_type_class_peek_parent(class);
	}

	t = g_list_first(list_ns);
	while (t) {
		ns = t->data;
		xmlNewNs(xmlnode, ns->href, ns->prefix);
		t = g_list_next(t);
	}

	xmlSetNs(xmlnode, xmlnode->nsDef);

	t = g_list_last(list_classes);
	while (t) {
		class = t->data;
		lasso_node_build_xmlNode_from_snippets(node, xmlnode,
				class->node_data->snippets, lasso_dump);
		t = g_list_previous(t);
	}

	xmlCleanNs(xmlnode);

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
	GList *elem;

	class = LASSO_NODE_GET_CLASS(object);
	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		for (snippet = class->node_data->snippets; snippet && snippet->name; snippet++) {
			void **value = G_STRUCT_MEMBER_P(object, snippet->offset);
			type = snippet->type & 0xff;

			if (snippet->type & SNIPPET_BOOLEAN)
				continue;
			if (snippet->type & SNIPPET_INTEGER)
				continue;

			if (*value == NULL)
				continue;

#if 0 /* to debug memory management problems */
			fprintf(stderr, "freeing %s/%s (at %p)\n",
					G_OBJECT_TYPE_NAME(object), snippet->name, *value);
#endif
			switch (type) {
				case SNIPPET_NODE:
				case SNIPPET_NAME_IDENTIFIER:
				case SNIPPET_NODE_IN_CHILD:
					lasso_node_destroy(*value);
					break;
				case SNIPPET_EXTENSION:
				case SNIPPET_LIST_NODES:
				case SNIPPET_LIST_CONTENT:
					elem = (GList*)(*value);
					while (elem) {
						if (type == SNIPPET_EXTENSION)
							xmlFreeNode(elem->data);
						if (type == SNIPPET_LIST_NODES)
							lasso_node_destroy(elem->data);
						if (type == SNIPPET_LIST_CONTENT)
							g_free(elem->data);
						elem = g_list_next(elem);
					}
					g_list_free(*value);
					break;
				case SNIPPET_CONTENT:
				case SNIPPET_TEXT_CHILD:
				case SNIPPET_ATTRIBUTE:
					g_free(*value);
					break;
				case SNIPPET_SIGNATURE:
					break; /* no real element here */
				default:
					fprintf(stderr, "%d\n", type);
					g_assert_not_reached();
			}

			*value = NULL;
		}
		class = g_type_class_peek_parent(class);
	}

	parent_class->dispose(object);
}

static void
lasso_node_finalize(GObject *object)
{
	parent_class->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoNode *node)
{
}

static void
class_init(LassoNodeClass *class)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS(class);

	parent_class = g_type_class_peek_parent(class);
	/* virtual public methods */
	class->destroy = lasso_node_impl_destroy;
	class->init_from_query = NULL;
	class->init_from_xml = lasso_node_impl_init_from_xml;
	class->get_sign_attr_name = NULL;

	/* virtual private methods */
	class->build_query = lasso_node_impl_build_query;
	class->get_xmlNode = lasso_node_impl_get_xmlNode;

	/* override */
	gobject_class->dispose = lasso_node_dispose;
	gobject_class->finalize = lasso_node_finalize;

	class->node_data = NULL;
}

GType
lasso_node_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoNodeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoNode),
			0,
			(GInstanceInitFunc) instance_init,
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

	doc = xmlParseMemory(dump, strlen(dump));
	node = lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc));
	xmlFreeDoc(doc);
	return node;
}

LassoNode*
lasso_node_new_from_soap(const char *soap)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *xmlnode;
	LassoNode *node = NULL;

	doc = xmlParseMemory(soap, strlen(soap));
	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "s", LASSO_SOAP_ENV_HREF);
	xpathObj = xmlXPathEvalExpression("//s:Body/*", xpathCtx);

	xmlnode = xpathObj->nodesetval->nodeTab[0];

	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr)
		node = lasso_node_new_from_xmlNode(xmlnode);

	xmlFreeDoc(doc);
	xmlXPathFreeContext(xpathCtx);
	xmlXPathFreeObject(xpathObj);

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
	char *prefix = NULL;
	char *typename;
	GType gtype;
	LassoNode *node;
	char *xsitype;
	int rc;

	if (xmlnode == NULL || xmlnode->ns == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Impossible to build LassoNode from xml node");
		return NULL;
	}

	if (strcmp(xmlnode->ns->href, LASSO_DISCO_HREF) == 0)
		prefix = "Disco";
	if (strcmp(xmlnode->ns->href, LASSO_LIB_HREF) == 0)
		prefix = "Lib";
	if (strcmp(xmlnode->ns->href, LASSO_LASSO_HREF) == 0)
		prefix = "";
	if (strcmp(xmlnode->ns->href, LASSO_SAML_ASSERTION_HREF) == 0)
		prefix = "Saml";
	if (strcmp(xmlnode->ns->href, LASSO_SAML_PROTOCOL_HREF) == 0)
		prefix = "Samlp";

	/* XXX: new Dst namespaces can be added dynamically; they should not
	 * be hardcoded here
	 */
	if (strcmp(xmlnode->ns->href, LASSO_PP_HREF) == 0)
		prefix = "Dst";
	if (strcmp(xmlnode->ns->href, LASSO_EP_HREF) == 0)
		prefix = "Dst";
	if (strcmp(prefix, "Dst") == 0 && strcmp(xmlnode->name, "Status") == 0)
		prefix = "Utility";
	if (strcmp(prefix, "Disco") == 0 && strcmp(xmlnode->name, "Status") == 0)
		prefix = "Utility";

	xsitype = xmlGetNsProp(xmlnode, "type", LASSO_XSI_HREF);
	if (xsitype) {
		/* XXX: should look for proper namespace prefix declaration
		 * and not assumes blindly that lib: is the liberty prefix;
		 * should also use the declared type to get the proper typename
		 * instead of falling back to good ol' xmlnode->name later.
		 * yada yada
		 */
		if (strncmp(xsitype, "lib:", 4) == 0)
			prefix = "Lib";
		xmlFree(xsitype);
	}

	if (prefix == NULL)
		return NULL;

	typename = g_strdup_printf("Lasso%s%s", prefix, xmlnode->name);

	gtype = g_type_from_name(typename);
	g_free(typename);
	if (gtype == 0)
		return NULL;

	node = g_object_new(gtype, NULL);
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
	while (*c != 0 && (isalnum(*c) || *c == '+' || *c == '/')) c++;
	while (*c == '=') c++; /* trailing = */

	if (*c == 0)
		return TRUE;

	return FALSE;
}

LassoMessageFormat
lasso_node_init_from_message(LassoNode *node, const char *message)
{
	char *msg;
	gboolean b64 = FALSE;
	int rc;

	msg = (char*)message;
	if (message[0] != 0 && is_base64(message)) {
		msg = g_malloc(strlen(message));
		rc = xmlSecBase64Decode(message, msg, strlen(message));
		if (rc >= 0) {
			b64 = TRUE;
		} else {
			/* oops; was not base64 after all */
			g_free(msg);
			msg = (char*)message;
		}
	}

	if (strchr(msg, '<')) {
		/* looks like xml */
		xmlDoc *doc;
		xmlNode *root;
		xmlXPathContext *xpathCtx = NULL;
		xmlXPathObject *xpathObj;

		doc = xmlParseMemory(msg, strlen(msg));
		if (doc == NULL)
			return LASSO_MESSAGE_FORMAT_UNKNOWN;
		root = xmlDocGetRootElement(doc);
		if (root->ns && strcmp(root->ns->href, LASSO_SOAP_ENV_HREF) == 0) {
			xpathCtx = xmlXPathNewContext(doc);
			xmlXPathRegisterNs(xpathCtx, "s", LASSO_SOAP_ENV_HREF);
			xpathObj = xmlXPathEvalExpression("//s:Body/*", xpathCtx);
			if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr ) {
				root = xpathObj->nodesetval->nodeTab[0];
			}
			xmlXPathFreeObject(xpathObj);
			xmlXPathFreeContext(xpathCtx);
		}
		lasso_node_init_from_xml(node, root);
		xmlFreeDoc(doc);
		if (xpathCtx)
			return LASSO_MESSAGE_FORMAT_SOAP;
		if (b64) {
			g_free(msg);
			return LASSO_MESSAGE_FORMAT_BASE64;
		}
		return LASSO_MESSAGE_FORMAT_XML;
	}

	if (strchr(msg, '&')) {
		/* looks like a query string */
		if (lasso_node_init_from_query(node, msg) == FALSE) {
			return LASSO_MESSAGE_FORMAT_ERROR;
		}
		return LASSO_MESSAGE_FORMAT_QUERY;
	}

	return LASSO_MESSAGE_FORMAT_UNKNOWN;
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
 * lasso_node_class_add_snippets:
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
		g_free(klass->node_data->node_name);
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
	klass->node_data->ns = xmlNewNs(NULL, href, prefix);
}

static void
lasso_node_build_xmlNode_from_snippets(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippets, gboolean lasso_dump)
{
	struct XmlSnippet *snippet;
	SnippetType type;
	xmlNode *t;
	xmlNs *xmlns;
	GList *elem;

	for (snippet = snippets; snippet && snippet->name; snippet++) {
		void *value = G_STRUCT_MEMBER(void*, node, snippet->offset);
		char *str = value;
		type = snippet->type & 0xff;

		if (lasso_dump == FALSE && snippet->type & SNIPPET_LASSO_DUMP)
			continue;

		if (value == NULL && ! (snippet->type & SNIPPET_BOOLEAN ||
					snippet->type & SNIPPET_INTEGER) )
			continue;

		/* XXX: not sure it is 64-bits clean */
		if (snippet->type & SNIPPET_BOOLEAN)
			str = GPOINTER_TO_INT(value) ? "true" : "false";
		if (snippet->type & SNIPPET_INTEGER)
			str = g_strdup_printf("%d", GPOINTER_TO_INT(value));

		switch (type) {
			case SNIPPET_ATTRIBUTE:
				xmlSetProp(xmlnode, snippet->name, str);
				break;
			case SNIPPET_TEXT_CHILD:
				xmlAddChild(xmlnode, xmlNewText(str));
				break;
			case SNIPPET_NODE:
				xmlAddChild(xmlnode, lasso_node_get_xmlNode(
							LASSO_NODE(value), lasso_dump));
				break;
			case SNIPPET_CONTENT:
				xmlNewTextChild(xmlnode, NULL, snippet->name, str);
				break;
			case SNIPPET_NAME_IDENTIFIER:
				xmlns = xmlNewNs(NULL, LASSO_LIB_HREF, LASSO_LIB_PREFIX);

				t = xmlAddChild(xmlnode, lasso_node_get_xmlNode(
							LASSO_NODE(value), lasso_dump));
				xmlNodeSetName(t, snippet->name);
				xmlSetNs(t, xmlns);
				break;
			case SNIPPET_NODE_IN_CHILD:
				t = xmlNewTextChild(xmlnode, NULL, snippet->name, NULL);
				xmlAddChild(t, lasso_node_get_xmlNode(
							LASSO_NODE(value), lasso_dump));
				break;
			case SNIPPET_LIST_NODES:
				elem = (GList *)value;
				while (elem) {
					xmlAddChild(xmlnode, lasso_node_get_xmlNode(
								LASSO_NODE(elem->data),
								lasso_dump));
					elem = g_list_next(elem);
				}
				break;
			case SNIPPET_LIST_CONTENT:
				/* sequence of simple elements (no children,
				 * no attrs, just content) */
				elem = (GList *)value;
				while (elem) {
					xmlNewTextChild(xmlnode, NULL,
							snippet->name, (char*)(elem->data));
					elem = g_list_next(elem);
				}
				break;
			case SNIPPET_EXTENSION:
				elem = (GList *)value;
				while (elem) {
					xmlAddChild(xmlnode, xmlCopyNode(elem->data, 1));
					elem = g_list_next(elem);
				}
				break;
			case SNIPPET_SIGNATURE:
				lasso_node_add_signature_template(node, xmlnode, snippet);
				break;
			case SNIPPET_INTEGER:
			case SNIPPET_BOOLEAN:
			case SNIPPET_LASSO_DUMP:
				g_assert_not_reached();
		}
		if (snippet->type & SNIPPET_INTEGER)
			g_free(str);
	}
}

static
void lasso_node_add_signature_template(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippet_signature)
{
	LassoNodeClass *klass = LASSO_NODE_GET_CLASS(node);
	lassoSignatureType sign_type;
	lassoSignatureType sign_method;
	xmlNode *signature = NULL, *reference, *key_info;
	char *uri;
	char *id;

	while (klass && LASSO_IS_NODE_CLASS(klass) && klass->node_data) {
		if (klass->node_data->sign_type_offset)
			break;
		klass = g_type_class_peek_parent(klass);
	}

	if (klass->node_data->sign_type_offset == 0)
		return;

	sign_type = G_STRUCT_MEMBER(
			lassoSignatureType, node,
			klass->node_data->sign_type_offset);
	sign_method = G_STRUCT_MEMBER(
			lassoSignatureType, node,
			klass->node_data->sign_method_offset);

	if (sign_type == LASSO_SIGNATURE_TYPE_NONE)
		return;

	if (sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1) {
		signature = xmlSecTmplSignatureCreate(NULL,
				xmlSecTransformExclC14NId,
				xmlSecTransformRsaSha1Id, NULL);
	} else {
		signature = xmlSecTmplSignatureCreate(NULL,
				xmlSecTransformExclC14NId,
				xmlSecTransformDsaSha1Id, NULL);
	}
	/* XXX: get out if signature == NULL ? */
	xmlAddChild(xmlnode, signature);

	id = G_STRUCT_MEMBER(char*, node, snippet_signature->offset);
	uri = g_strdup_printf("#%s", id);
	reference = xmlSecTmplSignatureAddReference(signature,
			xmlSecTransformSha1Id, NULL, uri, NULL);
	g_free(uri);

	/* add enveloped transform */
	xmlSecTmplReferenceAddTransform(reference,
			xmlSecTransformEnvelopedId);
	/* add exclusive C14N transform */
	xmlSecTmplReferenceAddTransform(reference,
			xmlSecTransformExclC14NId);

	if (sign_type == LASSO_SIGNATURE_TYPE_WITHX509) {
		/* add <dsig:KeyInfo/> */
		key_info = xmlSecTmplSignatureEnsureKeyInfo(
				signature, NULL);
		xmlSecTmplKeyInfoAddX509Data(key_info);
	}
}

static struct XmlSnippet*
find_xml_snippet_by_name(LassoNode *node, char *name)
{
	LassoNodeClass *class;
	struct XmlSnippet *snippet;

	class = LASSO_NODE_GET_CLASS(node);
	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		for (snippet = class->node_data->snippets;
				snippet && snippet->name && strcmp(snippet->name, name) != 0;
				snippet++) ;
		if (snippet && snippet->name)
			return snippet;
		class = g_type_class_peek_parent(class);
	}

	return NULL;
}

static int
find_path(LassoNode *node, char *path, LassoNode **value_node, struct XmlSnippet **snippet)
{
	char *s, *t;
	struct XmlSnippet *tsnippet = NULL;
	LassoNode *tnode = node;
	
	s = path;
	while (s-1) {
		t = strchr(s, '/');
		if (t) *t = 0;
		tsnippet = find_xml_snippet_by_name(tnode, s);
		if (t) {
			tnode = G_STRUCT_MEMBER(LassoNode*, tnode, tsnippet->offset);
			if (tnode == NULL)
				return -1;
		}
		s = t+1;
	}

	if (tsnippet == NULL)
		return -1;

	*snippet = tsnippet;
	*value_node = tnode;
	return 0;
}


static char*
get_value_by_path(LassoNode *node, char *path, struct XmlSnippet *xml_snippet)
{
	struct XmlSnippet *snippet;
	LassoNode *value_node;
	
	if (find_path(node, path, &value_node, &snippet) != 0)
		return NULL;

	*xml_snippet = *snippet;

	if (snippet->type & SNIPPET_BOOLEAN) {
		gboolean v = G_STRUCT_MEMBER(gboolean, value_node, snippet->offset);
		return v ? g_strdup("true") : g_strdup("false");
	} else if (snippet->type & SNIPPET_INTEGER) {
		int v = G_STRUCT_MEMBER(int, value_node, snippet->offset);
		return g_strdup_printf("%d", v);
	} else if (snippet->type == SNIPPET_NODE) {
		LassoNode *value = G_STRUCT_MEMBER(LassoNode*, value_node, snippet->offset);
		return lasso_node_build_query(value);
	} else if (snippet->type == SNIPPET_EXTENSION) {
		/* convert all of the <lib:Extension> into a string, already
		 * escaped for URI usage */
		GList *value = G_STRUCT_MEMBER(GList*, value_node, snippet->offset);
		xmlChar *s, *s2;
		GString *result = g_string_new("");
		while (value) {
			xmlNode *t = value->data;
			xmlNode *c;
			xmlAttr *a;

			/* attributes */
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
				g_string_append(result, c->name);
				g_string_append(result, "=");
				s = xmlNodeGetContent(c);
				s2 = xmlURIEscapeStr(s, NULL);
				g_string_append(result, s2);
				xmlFree(s2);
				xmlFree(s);
			}

			value = g_list_next(value);
		}
		if (result->len == 0) {
			g_string_free(result, TRUE);
			return NULL;
		}
		return g_string_free(result, FALSE);
	} else {
		char *value = G_STRUCT_MEMBER(char*, value_node, snippet->offset);
		if (value == NULL) return NULL;
		return g_strdup(value);
	}
	return NULL;
}

static int
set_value_at_path(LassoNode *node, char *path, char *query_value)
{
	struct XmlSnippet *snippet;
	LassoNode *value_node;
	void *value;
	
	if (find_path(node, path, &value_node, &snippet) != 0)
		return -1;

	value = G_STRUCT_MEMBER_P(value_node, snippet->offset);

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
	} else {
		(*(char**)value) = g_strdup(query_value);
	}

	return 0;
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
		memset(path, 0, 100);
		strncpy(path, query_snippets[i].path, 100);
		v = get_value_by_path(node, path, &xml_snippet);
		if (v && xml_snippet.type == SNIPPET_EXTENSION) {
			if (s->len)
				g_string_append(s, "&");
			g_string_append(s, v);
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
			t = xmlURIEscapeStr(v, NULL);
			g_string_append(s, t);
			xmlFree(t);
		}
		if (v)
			g_free(v);
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

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		if (class->node_data && class->node_data->query_snippets) {
			query_snippets = class->node_data->query_snippets;
			break;
		}
		class = g_type_class_peek_parent(class);
	}
	if (query_snippets == NULL)
		return FALSE;

	for (i=0; (field=query_fields[i]); i++) {
		t = strchr(field, '=');
		if (t == NULL)
			continue;
		*t = 0;

		for (j=0; query_snippets[j].path; j++) {
			char *field_name = query_snippets[j].field_name;
			char path[100];

			memset(path, 0, 100);
			strncpy(path, query_snippets[j].path, 100);

			if (field_name == NULL)
				field_name = query_snippets[j].path;
			if (strcmp(field, field_name) != 0)
				continue;
			set_value_at_path(node, path, t+1);
			break;
		}
		*t = '=';
	}

	return TRUE;
}

static void
xmlDeclareNs(xmlNode *root_node, xmlNode *node)
{
	xmlNs *ns;
	xmlNode *t;

	if (strcmp(node->name, "Signature") == 0)
		return;

	for (ns = node->nsDef; ns; ns = ns->next)
		if (strcmp(ns->prefix, "xsi") != 0)
			xmlNewNs(root_node, ns->href, ns->prefix);
	for (t = node->children; t; t = t->next)
		if (t->type == XML_ELEMENT_NODE)
			xmlDeclareNs(root_node, t);
}

static int
sameNs(xmlNs *ns1, xmlNs *ns2)
{
	return (ns1 == NULL && ns2 == NULL) || (ns1 && ns2 && strcmp(ns1->href, ns2->href) == 0);
}

static void
xmlUseNsDef(xmlNs *ns, xmlNode *node)
{
	xmlNode *t;
	xmlNs *ns2, *ns3;

	if (sameNs(ns, node->ns))
		node->ns = ns;

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
				ns3 = ns2;
				ns2->next = ns2->next->next;
				xmlFreeNs(ns3);
			}
		}
	}
}

/**
 * xmlCleanNs
 * @root_node: 
 *
 * xmlCleanNs removes duplicate xml namespace declarations and merge them on
 * the @root_node.
 **/
static void
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
