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

static GObjectClass *parent_class = NULL;

/*****************************************************************************/
/* virtual public methods                                                    */
/*****************************************************************************/

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
	xmlnode = lasso_node_get_xmlNode(node);
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
 * lasso_node_export_to_base64:
 * @node: a LassoNode
 * 
 * Base64 XML dump
 * 
 * Return value: a Base64 encoded export of the LassoNode
 **/
char*
lasso_node_export_to_base64(LassoNode *node)
{
	char *buffer, *ret;

	buffer = lasso_node_dump(node, "utf-8", 0);
	ret = xmlSecBase64Encode(buffer, strlen(buffer), 0);
	g_free(buffer);
	return ret;
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
char*
lasso_node_export_to_query(LassoNode *node,
		lassoSignatureMethod sign_method, const char *private_key_file)
{
	char *unsigned_query, *query;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
	g_return_val_if_fail (private_key_file != NULL, NULL);

	unsigned_query = lasso_node_build_query(node);
	query = lasso_query_sign(unsigned_query, sign_method, private_key_file);
	g_free(unsigned_query);

	return query;
}

/**
 * lasso_node_export_to_soap:
 * @node: a LassoNode
 * @private_key_file: path to private key for signature
 * @certificate_file: path to certificate for signature
 * 
 * Like lasso_node_export() method except that result is SOAP enveloped.
 * 
 * Return value: a SOAP enveloped export of the LassoNode
 **/
char*
lasso_node_export_to_soap(LassoNode *node,
		const char *private_key_file, const char *certificate_file)
{
	xmlDoc *doc;
	xmlNode *envelope, *body, *message, *sign_tmpl;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	xmlSecDSigCtx *dsig_ctx;
	char *ret;
	char *id_attr_name = NULL;

	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);

	message = lasso_node_get_xmlNode(node);

	sign_tmpl = xmlSecFindNode(message, xmlSecNodeSignature, xmlSecDSigNs);
	if (sign_tmpl && private_key_file) {
		doc = xmlNewDoc("1.0");
		xmlDocSetRootElement(doc, message);
		xmlSetTreeDoc(sign_tmpl, doc);
		if (LASSO_NODE_GET_CLASS(node)->get_sign_attr_name)
			id_attr_name = LASSO_NODE_GET_CLASS(node)->get_sign_attr_name();
		if (id_attr_name) {
			char *id_value = xmlGetProp(message, id_attr_name);
			xmlAttr *id_attr = xmlHasProp(message, id_attr_name);
			if (id_value) {
				xmlAddID(NULL, doc, id_value, id_attr);
				xmlFree(id_value);
			}
		}

		dsig_ctx = xmlSecDSigCtxCreate(NULL);
		dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(private_key_file,
				xmlSecKeyDataFormatPem,
				NULL, NULL, NULL);
		if (dsig_ctx->signKey == NULL) {
			/* XXX: file existence should actually be tested on
			 * LassoServer creation */
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED),
					private_key_file);
			xmlSecDSigCtxDestroy(dsig_ctx);
			return NULL;
		}
		if (certificate_file != NULL && certificate_file[0] != 0) {
			if (xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey, certificate_file,
						xmlSecKeyDataFormatPem) < 0) {
				message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED),
					certificate_file);
				xmlSecDSigCtxDestroy(dsig_ctx);
				return NULL;
			}
		}
		if (xmlSecDSigCtxSign(dsig_ctx, sign_tmpl) < 0) {
			message(G_LOG_LEVEL_CRITICAL,
					lasso_strerror(LASSO_DS_ERROR_SIGNATURE_FAILED),
					message->name);
			xmlSecDSigCtxDestroy(dsig_ctx);
			return NULL;
		}
		xmlSecDSigCtxDestroy(dsig_ctx);
		xmlUnlinkNode(message);
		xmlFreeDoc(doc);
	}

	envelope = xmlNewNode(NULL, "Envelope");
	xmlSetNs(envelope, xmlNewNs(envelope, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX));

	body = xmlNewTextChild(envelope, NULL, "Body", NULL);
	xmlAddChild(body, message);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, envelope, 0, 1, "utf-8");
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
 * @node: a LassoNode
 * @public_key_file: a public key (or a certificate) file
 * @ca_cert_chain_file: a CA certificate chain file
 * 
 * Verifies the node signature of @node.
 * 
 * Return value: 0 if signature is valid
 * a positive value if signature was not found or is invalid
 * a negative value if an error occurs during verification
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
lasso_node_get_xmlNode(LassoNode *node)
{
	LassoNodeClass *class;
	g_return_val_if_fail (LASSO_IS_NODE(node), NULL);
	class = LASSO_NODE_GET_CLASS(node);
	return class->get_xmlNode(node);
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

	class = LASSO_NODE_GET_CLASS(node);

	if (class->node_data == NULL)
		return 0;

	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		for (snippet = class->node_data->snippets; snippet && snippet->name; snippet++) {
			value = G_STRUCT_MEMBER_P(node, snippet->offset);
			if (snippet->type == SNIPPET_ATTRIBUTE)
				(*(char**)value) = xmlGetProp(xmlnode, snippet->name);
			if (snippet->type == SNIPPET_ATTRIBUTE_INT) {
				xmlChar *s = xmlGetProp(xmlnode, snippet->name);
				(*(int*)value) = atoi(s);
				xmlFree(s);
			}
			if (snippet->type == SNIPPET_ATTRIBUTE_BOOL) {
				xmlChar *s = xmlGetProp(xmlnode, snippet->name);
				(*(gboolean*)value) = (strcmp(s, "true") == 0);
				xmlFree(s);
			}
			if (snippet->type == SNIPPET_TEXT_CHILD)
				(*(char**)value) = xmlNodeGetContent(xmlnode);
		}

		for (t = xmlnode->children; t; t = t->next) {
			if (t->type != XML_ELEMENT_NODE)
				continue;

			for (snippet = class->node_data->snippets;
					snippet && snippet->name; snippet++) {
				value = G_STRUCT_MEMBER_P(node, snippet->offset);

				if (strcmp(t->name, snippet->name) != 0)
					continue;

				if (snippet->type == SNIPPET_NODE) {
					LassoNode **location = value;
					LassoNode *n = lasso_node_new_from_xmlNode(t);
					*location = n;
				}
				else if (snippet->type == SNIPPET_CONTENT)
					(*(char**)value) = xmlNodeGetContent(t);
				else if (snippet->type == SNIPPET_CONTENT_BOOL) {
					xmlChar *s = xmlNodeGetContent(t);
					(*(gboolean*)value) = (strcmp(s, "true") == 0);
					xmlFree(s);
				} else if (snippet->type == SNIPPET_CONTENT_INT) {
					xmlChar *s = xmlNodeGetContent(t);
					(*(gboolean*)value) = atoi(s);
					xmlFree(s);
				} else if (snippet->type == SNIPPET_NAME_IDENTIFIER)
					(*(LassoSamlNameIdentifier**)value) =
						lasso_saml_name_identifier_new_from_xmlNode(t);
				else if (snippet->type == SNIPPET_LIST_NODES) {
					xmlNode *ts;
					GList *s = NULL;
					for (ts = t->children; ts; ts = ts->next) {
						if (ts->type != XML_ELEMENT_NODE)
							continue;
						g_list_append(s, lasso_node_new_from_xmlNode(ts));
					}
					(*(GList**)value) = s;
				} else if (snippet->type == SNIPPET_LIST_CONTENT) {
					xmlNode *ts;
					GList *s = NULL;
					for (ts = t->children; ts; ts = ts->next) {
						if (ts->type != XML_ELEMENT_NODE)
							continue;
						g_list_append(s, xmlNodeGetContent(ts));
					}
					(*(GList**)value) = s;
				}
				break;
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
lasso_node_impl_get_xmlNode(LassoNode *node)
{
	LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
	xmlNode *xmlnode;
	xmlNs *ns;
	GList *list_ns = NULL, *t;

	if (class->node_data == NULL)
		return NULL;

	xmlnode = xmlNewNode(NULL, class->node_data->node_name);
	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		if (class->node_data->ns)
			list_ns = g_list_append(list_ns, class->node_data->ns);
		lasso_node_build_xmlNode_from_snippets(node, xmlnode, class->node_data->snippets);
		class = g_type_class_peek_parent(class);
	}

	t = g_list_first(list_ns);
	while (t) {
		ns = t->data;
		xmlNewNs(xmlnode, ns->href, ns->prefix);
		t = g_list_next(t);
	}

	fprintf(stderr, "ns: %s\n", xmlnode->nsDef->prefix);
	xmlSetNs(xmlnode, xmlnode->nsDef);

	xmlReconciliateNs(NULL, xmlnode);

	return xmlnode;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
lasso_node_dispose(GObject *object)
{
	LassoNodeClass *class;
	struct XmlSnippet *snippet;

	class = LASSO_NODE_GET_CLASS(object);
	while (class && LASSO_IS_NODE_CLASS(class) && class->node_data) {
		for (snippet = class->node_data->snippets; snippet && snippet->name; snippet++) {
			void **value = G_STRUCT_MEMBER_P(object, snippet->offset);

			if (*value == NULL)
				continue;
			switch (snippet->type) {
				case SNIPPET_ATTRIBUTE_BOOL:
				case SNIPPET_ATTRIBUTE_INT:
				case SNIPPET_CONTENT_BOOL:
				case SNIPPET_CONTENT_INT:
					break;
				case SNIPPET_CONTENT:
				case SNIPPET_TEXT_CHILD:
				case SNIPPET_ATTRIBUTE:
					g_free(*value);
					break;
				case SNIPPET_NODE:
				case SNIPPET_NAME_IDENTIFIER:
					g_object_unref(*value);
					break;
				case SNIPPET_LIST_NODES:
				case SNIPPET_LIST_CONTENT:
					/* XXX: memory management for lists */
					break;
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
 * The main LassoNode constructor.
 * 
 * Return value: a new node
 **/
LassoNode*
lasso_node_new()
{
	return g_object_new(LASSO_TYPE_NODE, NULL);
}

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
 * Builds a new LassoNode from an xmlNode.
 * 
 * Return value: a new node
 **/
LassoNode*
lasso_node_new_from_xmlNode(xmlNode *xmlnode)
{
	char *prefix;
	char *typename;
	GType gtype;
	LassoNode *node;
	char *xsitype;
	int rc;

	/* XXX I'm not sure I can access ->ns like this */

	if (xmlnode == NULL || xmlnode->ns == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Impossible to build LassoNode from xml node");
		return NULL;
	}

	if (strcmp(xmlnode->ns->href, LASSO_LIB_HREF) == 0)
		prefix = "Lib";
	if (strcmp(xmlnode->ns->href, LASSO_LASSO_HREF) == 0)
		prefix = "";
	if (strcmp(xmlnode->ns->href, LASSO_SAML_ASSERTION_HREF) == 0)
		prefix = "Saml";
	if (strcmp(xmlnode->ns->href, LASSO_SAML_PROTOCOL_HREF) == 0)
		prefix = "Samlp";

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

	typename = g_strdup_printf("Lasso%s%s", prefix, xmlnode->name);

	gtype = g_type_from_name(typename);
	g_free(typename);
	if (gtype == 0)
		return NULL;

	node = g_object_new(gtype, NULL);
	rc = lasso_node_init_from_xml(node, xmlnode);
	if (rc) {
		g_object_unref(node);
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

void
init_xml_with_snippets(xmlNode *node, struct XmlSnippetObsolete *snippets)
{
	xmlNode *t;
	int i;

	for (i = 0; snippets[i].name; i++) {
		if (snippets[i].type == SNIPPET_ATTRIBUTE)
			*(snippets[i].value) = xmlGetProp(node, snippets[i].name);
	}

	for (t = node->children; t; t = t->next) {
		if (t->type != XML_ELEMENT_NODE)
			continue;

		for (i = 0; snippets[i].name; i++) {
			if (strcmp(t->name, snippets[i].name) != 0)
				continue;
			else if (snippets[i].type == SNIPPET_NODE)
				*(snippets[i].value) = lasso_node_new_from_xmlNode(t);
			else if (snippets[i].type == SNIPPET_CONTENT)
				*(snippets[i].value) = xmlNodeGetContent(t);
			else if (snippets[i].type == SNIPPET_NAME_IDENTIFIER)
				*(snippets[i].value) = (void*)
					lasso_saml_name_identifier_new_from_xmlNode(t);
			else if (snippets[i].type == SNIPPET_LIST_NODES) {
				xmlNode *ts;
				GList *s = NULL;
				for (ts = t->children; ts; ts = ts->next) {
					if (ts->type != XML_ELEMENT_NODE)
						continue;
					g_list_append(s, lasso_node_new_from_xmlNode(ts));
				}
				*(snippets[i].value) = s;
			} else if (snippets[i].type == SNIPPET_LIST_CONTENT) {
				xmlNode *ts;
				GList *s = NULL;
				for (ts = t->children; ts; ts = ts->next) {
					if (ts->type != XML_ELEMENT_NODE)
						continue;
					g_list_append(s, xmlNodeGetContent(ts));
				}
				*(snippets[i].value) = s;
			}
			break;
		}
	}
}

void
build_xml_with_snippets(xmlNode *node, struct XmlSnippetObsolete *snippets)
{
	int i;

	for (i = 0; snippets[i].name; i++) {
		if (*(snippets[i].value) == NULL)
			continue;
		else if (snippets[i].type == SNIPPET_ATTRIBUTE)
			xmlSetProp(node, snippets[i].name, (char*)(*(snippets[i].value)));
		else if (snippets[i].type == SNIPPET_NODE)
			xmlAddChild(node, lasso_node_get_xmlNode(
						LASSO_NODE(*(snippets[i].value))));
		else if (snippets[i].type == SNIPPET_CONTENT)
			xmlNewTextChild(node, NULL, snippets[i].name, 
					(char*)(*(snippets[i].value)));
		else if (snippets[i].type == SNIPPET_NAME_IDENTIFIER) {
			xmlNode *t;
			xmlNs *xmlns;
			xmlns = xmlNewNs(node, LASSO_LIB_HREF, LASSO_LIB_PREFIX);

			t = xmlAddChild(node, lasso_node_get_xmlNode(
						LASSO_NODE(*(snippets[i].value))));
			xmlNodeSetName(t, snippets[i].name);
			xmlSetNs(t, xmlns);
		} else if (snippets[i].type == SNIPPET_LIST_NODES) {
			GList *elem = (GList *)(*(snippets[i].value));
			while (elem) {
				xmlAddChild(node, lasso_node_get_xmlNode(LASSO_NODE(elem->data)));
				elem = g_list_next(elem);
			}
		} else if (snippets[i].type == SNIPPET_LIST_CONTENT) {
			/* sequence of simple elements (no children, no attrs, just content) */
			GList *elem = (GList *)(*(snippets[i].value));
			while (elem) {
				xmlNewTextChild(node, NULL, snippets[i].name, (char*)(elem->data));
				elem = g_list_next(elem);
			}
		}
	}
}


/**
 * lasso_node_class_add_snippets
 * @klass: self
 * @snippets: array of XmlSnippet (NULL terminated)
 **/
void
lasso_node_class_add_snippets(LassoNodeClass *klass, struct XmlSnippet *snippets)
{
	klass->node_data->snippets = snippets;
}


void
lasso_node_class_set_nodename(LassoNodeClass *klass, char *name)
{
	if (klass->node_data->node_name)
		g_free(klass->node_data->node_name);
	klass->node_data->node_name = g_strdup(name);
}

void
lasso_node_class_set_ns(LassoNodeClass *klass, char *href, char *prefix)
{
	if (klass->node_data->ns)
		xmlFreeNs(klass->node_data->ns);
	klass->node_data->ns = xmlNewNs(NULL, href, prefix);
}


void
lasso_node_build_xmlNode_from_snippets(LassoNode *node, xmlNode *xmlnode,
		struct XmlSnippet *snippets)
{
	struct XmlSnippet *snippet;

	for (snippet = snippets; snippet && snippet->name; snippet++) {
		void *value = G_STRUCT_MEMBER(void*, node, snippet->offset);

		if (value == NULL && (snippet->type != SNIPPET_ATTRIBUTE_INT &&
					snippet->type != SNIPPET_CONTENT_BOOL &&
					snippet->type != SNIPPET_CONTENT_INT &&
					snippet->type != SNIPPET_ATTRIBUTE_BOOL))
			continue;

		if (snippet->type == SNIPPET_ATTRIBUTE)
			xmlSetProp(xmlnode, snippet->name, (char*)value);
		else if (snippet->type == SNIPPET_ATTRIBUTE_INT) {
			char t[40];
			g_snprintf(t, 40, "%d", GPOINTER_TO_INT(value));
			xmlSetProp(xmlnode, snippet->name, t);
		} else if (snippet->type == SNIPPET_ATTRIBUTE_BOOL) {
			char *s;
			s = GPOINTER_TO_INT(value) ? "true" : "false";
			xmlSetProp(xmlnode, snippet->name, s);
		} else if (snippet->type == SNIPPET_TEXT_CHILD)
			xmlAddChild(xmlnode, xmlNewText((char*)value));
		else if (snippet->type == SNIPPET_NODE)
			xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value)));
		else if (snippet->type == SNIPPET_CONTENT)
			xmlNewTextChild(xmlnode, NULL, snippet->name, (char*)(value));
		else if (snippet->type == SNIPPET_CONTENT_BOOL) {
			char *s;
			s = GPOINTER_TO_INT(value) ? "true" : "false";
			xmlNewTextChild(xmlnode, NULL, snippet->name, s);
		} else if (snippet->type == SNIPPET_CONTENT_INT) {
			char t[40];
			g_snprintf(t, 40, "%d", GPOINTER_TO_INT(value));
			xmlNewTextChild(xmlnode, NULL, snippet->name, t);
		} else if (snippet->type == SNIPPET_NAME_IDENTIFIER) {
			xmlNode *t;
			xmlNs *xmlns;
			xmlns = xmlNewNs(NULL, LASSO_LIB_HREF, LASSO_LIB_PREFIX);

			t = xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value)));
			xmlNodeSetName(t, snippet->name);
			xmlSetNs(t, xmlns);
		} else if (snippet->type == SNIPPET_LIST_NODES) {
			GList *elem = (GList *)value;
			while (elem) {
				xmlAddChild(xmlnode,
						lasso_node_get_xmlNode(LASSO_NODE(elem->data)));
				elem = g_list_next(elem);
			}
		} else if (snippet->type == SNIPPET_LIST_CONTENT) {
			/* sequence of simple elements (no children, no attrs, just content) */
			GList *elem = (GList *)value;
			while (elem) {
				xmlNewTextChild(xmlnode, NULL, snippet->name, (char*)(elem->data));
				elem = g_list_next(elem);
			}
		}
	}
}

