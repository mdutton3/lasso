/* $Id$
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * SECTION:wsse_username_token
 *
 * Transmit username and password credential as a WS-Security token. The password can be transmitted
 * as cleartext or using a digest mode. It also allows to derive encryption and HMAC signing keys.
 */

/**
 * LassoWsseUsernameToken:
 * @Id: the identifier of the UsernameToken
 * @Username: the username
 * @Nonce: a nonce used to compute the digest of the password
 * @Created: the timestamp for the generation of the token, also used in the digest of the password
 * @Salt: the salt for generating derived key
 * @Iteration: how many times to apply SHA1 for generating derivated key
 *
 */

#include "./wsse_username_token.h"
#include "../idwsf_strings.h"
#include <xmlsec/xmltree.h>
#include <openssl/sha.h>
#include <glib.h>
#include "../string.h"
#include "../private.h"
#include "../../utils.h"
#include "../../errors.h"

struct _LassoWsseUsernameTokenPrivate {
	char *Password;
	LassoWsseUsernameTokenPasswordType PasswordType;
};

typedef struct _LassoWsseUsernameTokenPrivate LassoWsseUsernameTokenPrivate;

#define LASSO_WSSE_USERNAME_TOKEN_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_WSSE_USERNAME_TOKEN, \
					 LassoWsseUsernameTokenPrivate))

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoWsseUsernameToken, Id), NULL,
		LASSO_WSU_PREFIX, LASSO_WSU_HREF},
	{ "Username", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsseUsernameToken, Username), NULL,
		NULL, NULL},
	{ "Nonce", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsseUsernameToken, Nonce), NULL, NULL,
		NULL},
	{ "Created", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsseUsernameToken, Created), NULL, NULL,
		NULL},
	{ "Salt", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsseUsernameToken, Salt), NULL,
		LASSO_WSSE11_PREFIX, LASSO_WSSE11_HREF},
	{ "Iteration", SNIPPET_CONTENT | SNIPPET_INTEGER, G_STRUCT_OFFSET(LassoWsseUsernameToken,
			Iteration), NULL, LASSO_WSSE11_PREFIX, LASSO_WSSE11_HREF},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoWsseUsernameToken, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc = 0;
	xmlNode *password;
	xmlChar *kind;
	LassoWsseUsernameTokenPrivate *private = LASSO_WSSE_USERNAME_TOKEN_GET_PRIVATE(node);

	password = xmlSecFindNode(xmlnode, (xmlChar*)"Password", (xmlChar*)LASSO_WSSE1_HREF);
	if (password) {
		xmlChar *content = xmlNodeGetContent(password);
		kind = xmlGetNsProp(password, (xmlChar*)"Type", (xmlChar*)LASSO_WSSE1_HREF);
		lasso_assign_string(private->Password, (char*)content);
		if (kind && strcmp((char*)kind, LASSO_WSSE_USERNAME_TOKEN_PROFILE_PASSWORD_TEXT)) {
			private->PasswordType = LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_DIGEST;
		} else if (kind && strcmp((char*)kind, LASSO_WSSE_USERNAME_TOKEN_PROFILE_PASSWORD_TEXT)) {
			private->PasswordType = LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_TEXT;
		} else {
			rc = -1;
		}
		lasso_release_xml_string(content);
		lasso_release_xml_string(kind);
	}

	rc = parent_class->init_from_xml(node, xmlnode);

	return 0;
}

static void
instance_init(LassoWsseUsernameToken *wsse_username_token)
{
	wsse_username_token->attributes =
		g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoWsseUsernameTokenClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->init_from_xml = init_from_xml;
	lasso_node_class_set_nodename(nclass, "UsernameToken");
	lasso_node_class_set_ns(nclass, LASSO_WSSE1_HREF, LASSO_WSSE1_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_wsse_username_token_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoWsseUsernameTokenClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsseUsernameToken),
			0,
			(GInstanceInitFunc)instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsseUsernameToken", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_wsse_username_tokne_new:
 *
 * Create a new #LassoWsseUsernameToken object.
 *
 * Return value: a newly created #LassoWsseUsernameToken object
 */
LassoWsseUsernameToken*
lasso_wsse_username_token_new()
{
	LassoWsseUsernameToken *node;

	node = (LassoWsseUsernameToken*)g_object_new(LASSO_TYPE_WSSE_USERNAME_TOKEN, NULL);
	node->Id = lasso_build_unique_id(40);
	node->Created = lasso_get_current_time();

	return node;
}

/**
 * lasso_wsse_username_token_reset_nonce:
 * @wsse_username_token: a #LassoWsseUsernameToken object
 *
 * Generate a random nonce.
 */
void
lasso_wsse_username_token_reset_nonce(LassoWsseUsernameToken *wsse_username_token)
{
	guint32 nonce[16];
	int i;

	for (i=0; i < 16; i++) {
		nonce[i] = g_random_int();
	}

	wsse_username_token->Nonce = g_base64_encode((guchar*)nonce, sizeof(nonce));
}


/**
 * lasso_wsse_username_token_set_password_kind:
 * @wsse_username_token: a #LassoWsseUsernameToken object
 * @password_type: a #LassoWsseUsernameTokenPasswordType enumeration
 *
 * Set the way to transmit password, that is either cleartext or digest.
 */
void
lasso_wsse_username_token_set_password_kind(LassoWsseUsernameToken *wsse_username_token,
		LassoWsseUsernameTokenPasswordType password_type)
{
	LassoWsseUsernameTokenPrivate *private =
		LASSO_WSSE_USERNAME_TOKEN_GET_PRIVATE(wsse_username_token);

	private->PasswordType = password_type;
}

static char *
_lasso_wsse_username_token_compute_digest(LassoWsseUsernameToken *wsse_username_token,
		char *password)
{
	guchar *nonce;
	guint nonce_len = 0;
	guint created_len = 0;
	guint password_len = 0;
	guchar *buffer;
	gchar *result;

	if (wsse_username_token->Nonce) {
		nonce = g_base64_decode((gchar*)wsse_username_token->Nonce, &nonce_len);
	}
	if (wsse_username_token->Created) {
		created_len = strlen(wsse_username_token->Created);
	}
	if (password) {
		password_len = strlen(password);
	}

	buffer = g_malloc(nonce_len + created_len + password ? strlen(password) : 0);
	memcpy(buffer, nonce, nonce_len);
	memcpy(buffer + nonce_len, wsse_username_token->Created, created_len);
	memcpy(buffer + nonce_len + created_len, password, password_len);
	result = g_base64_encode((guchar*)buffer, nonce_len + created_len + password_len);
	lasso_release(buffer);

	return result;
}


/**
 * lasso_wsse_username_token_set_password:
 * @wsse_username_token: a #LassoWsseUsernameToken object
 * @password: an UTF-8 string
 *
 * Set the password using the given UTF-8 string. If password kind is digest, compute the digest
 * SHA1(nonce + created + password), convert to Base64 and set it as the password. If nonce or
 * created are NULL, the empty string is used.
 *
 * Return value: 0 if successfull, an error code otherwise.
 */
int
lasso_wsse_username_token_set_password(LassoWsseUsernameToken *wsse_username_token, char *password)
{
	LassoWsseUsernameTokenPrivate *private =
		LASSO_WSSE_USERNAME_TOKEN_GET_PRIVATE(wsse_username_token);

	switch (private->PasswordType) {
		case LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_DIGEST:
			lasso_assign_string(private->Password,
					_lasso_wsse_username_token_compute_digest(
						wsse_username_token, password));
			break;
		case LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_TEXT:
			lasso_assign_string(private->Password, password);
			break;
		default:
			return LASSO_ERROR_UNDEFINED;
	}

	return 0;
}

int
lasso_wsse_username_token_check_password(LassoWsseUsernameToken *wsse_username_token, char
		*password)
{
	LassoWsseUsernameTokenPrivate *private =
		LASSO_WSSE_USERNAME_TOKEN_GET_PRIVATE(wsse_username_token);
	int rc = 0;
	char *digest;

	switch (private->PasswordType) {
		case LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_DIGEST:
			digest = _lasso_wsse_username_token_compute_digest(wsse_username_token, password);
			if (strcmp(private->Password, digest) != 0) {
				rc = LASSO_WSSEC_ERROR_BAD_PASSWORD;
			}
			lasso_release(digest);
			break;
		case LASSO_WSSE_USERNAME_TOKEN_PASSWORD_TYPE_TEXT:
			if (strcmp(private->Password, password) != 0) {
				return LASSO_WSSEC_ERROR_BAD_PASSWORD;
			}
			break;
		default:
			return LASSO_ERROR_UNDEFINED;
	}
	return rc;
}

/**
 * lasso_wsse_username_token_derive_key:
 * @wsse_username_token: a #LassoWsseUsernameToken object
 * @password: the known password
 *
 * Generate a derived 128bit key using the password and setting from the UsernameToken.
 *
 * Return value: a 20 byte octet string.
 */
guchar*
lasso_wsse_username_token_derive_key(LassoWsseUsernameToken *wsse_username_token,
		char *password)
{
	guchar *salt;
	gsize salt_len;
	guchar *result = NULL;
	guint iteration;
	guchar *buffer;
	gsize buffer_len;
	guint password_len;
	guchar hash1[20], hash2[20];

	if (! wsse_username_token->Salt)
		goto exit;
	if (wsse_username_token->Iteration <= 0)
		iteration = 1000;
	else
		iteration = wsse_username_token->Iteration;
	salt = g_base64_decode(wsse_username_token->Salt, &salt_len);
	if (salt_len < 8)
		goto exit;
	password_len = strlen(password);
	buffer = g_malloc(salt_len + password_len);
	memcpy(buffer, salt, salt_len);
	memcpy(buffer + salt_len, password, password_len);
	buffer_len = salt_len + password_len;
	if (iteration & 1) {
		SHA1(buffer, buffer_len, hash1);
	} else {
		SHA1(buffer, buffer_len, hash2);
	}
	iteration--;
	while (iteration) {
		if (iteration & 1) {
			SHA1(hash2, 20, hash1);
		} else {
			SHA1(hash1, 20, hash2);
		}
		iteration--;
	}
	lasso_release(buffer);
	result = g_malloc(20);
	memcpy(result, hash1, 20);

exit:
	lasso_release(salt);
	return result;

}
