/*
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2011 Entr'ouvert
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

#include "key.h"
#include "keyprivate.h"
#include "xml/private.h"
#include "xmlsec/xmltree.h"

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

struct _LassoKeyPrivate {
	enum _LassoKeyType type;
	union {
		LassoSignatureContext signature;
	} context;
};

#define LASSO_KEY_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_KEY, LassoKeyPrivate))

static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoKey *key)
{
	key->private_data = LASSO_KEY_GET_PRIVATE(key);
}

static void
dispose(GObject *g_object)
{
	LassoKey *key = (LassoKey*)g_object;

	if (key->private_data) {
		switch (key->private_data->type) {
			case LASSO_KEY_TYPE_FOR_SIGNATURE:
				lasso_assign_new_signature_context(
						key->private_data->context.signature,
						LASSO_SIGNATURE_CONTEXT_NONE);
				break;
		}
	}

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(key));
}

static void
class_init(LassoKeyClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Key");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(LassoKeyPrivate));
	G_OBJECT_CLASS(klass)->dispose = dispose;
}

GType
lasso_key_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoKeyClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoKey),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoKey", &this_info, 0);
	}
	return this_type;
}

static LassoKey*
lasso_key_new()
{
	return g_object_new(LASSO_TYPE_KEY, NULL);
}

static LassoKey*
lasso_key_new_for_signature_from_context(LassoSignatureContext context) {
	LassoKey *key = lasso_key_new();

	key->private_data->type = LASSO_KEY_TYPE_FOR_SIGNATURE;
	lasso_assign_new_signature_context(
			key->private_data->context.signature, context);
	if (! lasso_validate_signature_context(key->private_data->context.signature)) {
		lasso_release_gobject(key);
	}
	return key;
}

/**
 * lasso_key_new_for_signature_from_file:
 * @filename_or_buffer: a file path of a string containing the key PEM or Base64 encoded
 * @password: an eventual password to decoded the private key contained in @buffer
 * @signature_method: the signature method to associate to this key
 * @certificate: a certificate as a file path or PEM encoded in a NULL-terminated string, to
 * associate with the key, it will be used to fill the KeyInfo node in an eventual signature.
 *
 * Create a new #LassoKey object, you can use it to sign XML message or to specify the key of a
 * provider.
 *
 * Return value:(transfer full): a newly allocated #LassoKey object
 */
LassoKey*
lasso_key_new_for_signature_from_file(char *filename_or_buffer,
		char *password,
		LassoSignatureMethod signature_method,
		char *certificate) {
	return lasso_key_new_for_signature_from_context(
			lasso_make_signature_context_from_path_or_string(filename_or_buffer,
				password,
				signature_method,
				certificate));
}

/**
 * lasso_key_new_for_signature_from_memory:
 * @buffer: a byte buffer of size @size
 * @size: the size of @buffer
 * @password: an eventual password to decoded the private key contained in @buffer
 * @signature_method: the signature method to associate to this key
 * @certificate: a certificate as a file path or PEM encoded in a NULL-terminated string, to
 * associate with the key, it will be used to fill the KeyInfo node in an eventual signature.
 *
 * Create a new #LassoKey object, you can use it to sign XML message or to specify the key of a
 * provider.
 *
 * Return value:(transfer full): a newly allocated #LassoKey object
 */
LassoKey*
lasso_key_new_for_signature_from_memory(const void *buffer,
		size_t size,
		char *password,
		LassoSignatureMethod signature_method,
		char *certificate)
{
	return lasso_key_new_for_signature_from_context(
			lasso_make_signature_context_from_buffer(buffer,
				size,
				password,
				signature_method,
				certificate));
}

/**
 * lasso_key_new_for_signature_from_base64_string:
 * @base64_string: a NULL-terminated string containing a base64 encode representation of the key
 * @password: an eventual password to decoded the private key contained in @buffer
 * @signature_method: the signature method to associate to this key
 * @certificate: a certificate as a file path or PEM encoded in a NULL-terminated string, to
 * associate with the key, it will be used to fill the KeyInfo node in an eventual signature.
 *
 * Create a new #LassoKey object, you can use it to sign XML message or to specify the key of a
 * provider.
 *
 * Return value:(transfer full): a newly allocated #LassoKey object
 */
LassoKey*
lasso_key_new_for_signature_from_base64_string(char *base64_string,
		char *password,
		LassoSignatureMethod signature_method,
		char *certificate)
{
	LassoKey *key = NULL;
	char *buffer = NULL;
	int length = 0;

	if (lasso_base64_decode(base64_string, &buffer, &length)) {
		key = lasso_key_new_for_signature_from_context(
				lasso_make_signature_context_from_buffer(buffer,
					length,
					password,
					signature_method,
					certificate));
		lasso_release_string(buffer);
	}
	return key;
}

static xmlNode *
find_xmlnode_with_saml2_id(xmlNode *xmlnode, const char *id)
{
	xmlNode *found = NULL;
	xmlNode *t;

	if (! xmlnode)
		return NULL;

	if (xmlHasProp(xmlnode, BAD_CAST "ID")) {
		xmlChar *value;

		value = xmlGetProp(xmlnode, BAD_CAST "ID");
		if (lasso_strisequal((char*)value, id)) {
			found = xmlnode;
		}
		xmlFree(value);
	}
	if (found) {
		return found;
	}
	t = xmlSecGetNextElementNode(xmlnode->children);
	while (t) {
		found = find_xmlnode_with_saml2_id(t, id);
		if (found) {
			return found;
		}
		t = xmlSecGetNextElementNode(t->next);
	}
	return NULL;
}

/**
 * lasso_key_saml2_xml_verify:
 * @key: a #LassoKey object
 * @id: the value of the ID attribute of signed node
 * @document: the document containing the signed node
 *
 * Verify the first signature node child of the node with the given id. It follows from the profile
 * of XMLDsig used by the SAML 2.0 specification.
 *
 * Return value: 0 if the signature validate, an error code otherwise.
 */
lasso_error_t
lasso_key_saml2_xml_verify(LassoKey *key, char *id, xmlNode *document)
{
	xmlNode *signed_node;
	LassoSignatureContext signature_context;


	signed_node = find_xmlnode_with_saml2_id(document, id);
	if (! signed_node) {
		return LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML;
	}
	signature_context = lasso_key_get_signature_context(key);
	return lasso_verify_signature(signed_node, signed_node->doc, "ID", NULL,
			signature_context.signature_key, NO_OPTION, NULL);
}

/**
 * lasso_key_saml2_xml_sign:
 * @key: a #LassoKey object
 * @id: the value of the ID attribute of signed node
 * @document: the document containing the signed node
 *
 * Sign the first signature node child of the node with the given id. It no signature node is found
 * a new one is added at the end of the children list of the signed node.
 *
 * The passed document node is modified in-place.
 *
 * Return value: The modified xmlNode object, or NULL if the signature failed.
 */
xmlNode*
lasso_key_saml2_xml_sign(LassoKey *key, const char *id, xmlNode *document)
{
	xmlNode *signed_node;
	LassoSignatureContext signature_context;

	signed_node = find_xmlnode_with_saml2_id(document, id);
	if (! signed_node) {
		return NULL;
	}
	signature_context = lasso_key_get_signature_context(key);
	lasso_xmlnode_add_saml2_signature_template(signed_node, signature_context, id);
	if (lasso_sign_node(signed_node, signature_context,
			"ID", id) == 0) {
		return document;
	} else {
		return NULL;
	}
}

/**
 * lasso_key_query_verify:
 * key: a #LassoKey object
 * query: a raw HTTP query string
 *
 * Check if this query string contains a proper SAML2 signature for this key.
 *
 * Return value: 0 if a valid signature was found, an error code otherwise.
 */
lasso_error_t
lasso_key_query_verify(LassoKey *key, const char *query)
{
	LassoSignatureContext signature_context;
	lasso_bad_param(KEY, key);

	signature_context = lasso_key_get_signature_context(key);
	if (! lasso_validate_signature_context(signature_context))
		return LASSO_ERROR_UNDEFINED;
	return lasso_saml2_query_verify_signature(query, signature_context.signature_key);
}

/**
 * lasso_key_query_verify:
 * key: a #LassoKey object
 * query: a raw HTTP query string
 *
 * Sign the given query string using the given key.
 *
 * Return value: the signed query string.
 */
char*
lasso_key_query_sign(LassoKey *key, const char *query)
{
	LassoSignatureContext signature_context;

	if (! LASSO_IS_KEY(key))
		return NULL;
	signature_context = lasso_key_get_signature_context(key);
	if (! lasso_validate_signature_context(signature_context))
		return NULL;
	return lasso_query_sign((char*)query, signature_context);
}

/**
 * lasso_key_get_signature_context:
 * @key: a #LassoKey object
 *
 * Private method to extract the signature context embedded in a LassoKey object.
 *
 * Return value: a #LassoSignatureContext structure value.
 */
LassoSignatureContext
lasso_key_get_signature_context(LassoKey *key) {
	if (key->private_data && key->private_data->type == LASSO_KEY_TYPE_FOR_SIGNATURE) {
		return key->private_data->context.signature;
	}
	return LASSO_SIGNATURE_CONTEXT_NONE;
}

/**
 * lasso_key_get_key_type:
 * @key: a #LassoKey object
 *
 * Return the type of key, i.e. which operation it supports.
 */
LassoKeyType
lasso_key_get_key_type(LassoKey *key) {
	lasso_return_val_if_fail(LASSO_IS_KEY(key),
			LASSO_KEY_TYPE_FOR_SIGNATURE);
	return key->private_data->type;
}
