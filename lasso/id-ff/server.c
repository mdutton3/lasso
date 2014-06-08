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

/**
 * SECTION:server
 * @short_description: Representation of the current server
 *
 * It holds the data about a provider, other providers it knows, which
 * certificates to use, etc.
 **/

#include "../xml/private.h"
#include <xmlsec/base64.h>
#include <xmlsec/xmltree.h>

#include <config.h>
#include "server.h"
#include "providerprivate.h"
#include "serverprivate.h"
#include "../saml-2.0/serverprivate.h"
#include "../utils.h"
#include "../debug.h"
#include "../lasso_config.h"
#ifdef LASSO_WSF_ENABLED
#include "../id-wsf/id_ff_extensions_private.h"
#include "../id-wsf-2.0/serverprivate.h"
#endif

#define RSA_SHA1 "RSA_SHA1"
#define DSA_SHA1 "DSA_SHA1"
#define HMAC_SHA1 "HMAC_SHA1"

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

static gint
lasso_server_add_provider_helper(LassoServer *server, LassoProviderRole role,
		const gchar *metadata, const gchar *public_key, const gchar *ca_cert_chain,
		LassoProvider *(*provider_constructor)(LassoProviderRole role,
		const char *metadata, const char *public_key, const char *ca_cert_chain))
{
	LassoProvider *provider;

	g_return_val_if_fail(LASSO_IS_SERVER(server), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(metadata != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	provider = provider_constructor(role, metadata, public_key, ca_cert_chain);
	if (provider == NULL) {
		return critical_error(LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED);
	}
	provider->role = role;

	if (LASSO_PROVIDER(server)->private_data->conformance == LASSO_PROTOCOL_SAML_2_0 &&
			provider->private_data->conformance != LASSO_PROTOCOL_SAML_2_0) {
		lasso_node_destroy(LASSO_NODE(provider));
		return LASSO_SERVER_ERROR_ADD_PROVIDER_PROTOCOL_MISMATCH;
	}

	if (LASSO_PROVIDER(server)->private_data->conformance == LASSO_PROTOCOL_LIBERTY_1_2 &&
			provider->private_data->conformance > LASSO_PROTOCOL_LIBERTY_1_2) {
		lasso_node_destroy(LASSO_NODE(provider));
		return LASSO_SERVER_ERROR_ADD_PROVIDER_PROTOCOL_MISMATCH;
	}

	return lasso_server_add_provider2(server, provider);
}

/**
 * lasso_server_add_provider:
 * @server: a #LassoServer
 * @role: provider role, identity provider or service provider
 * @metadata: path to the provider metadata file
 * @public_key:(allow-none): provider public key file (may be a certificate) or NULL
 * @ca_cert_chain:(allow-none): provider CA certificate chain file or NULL
 *
 * Creates a new #LassoProvider and makes it known to the @server
 *
 * Return value: 0 on success; a negative value if an error occured.
 **/
gint
lasso_server_add_provider(LassoServer *server, LassoProviderRole role,
		const gchar *metadata, const gchar *public_key, const gchar *ca_cert_chain)
{
	return lasso_server_add_provider_helper(server, role, metadata,
			public_key, ca_cert_chain, lasso_provider_new);
}

/**
 * lasso_server_add_provider2:
 * @server: a #LassoServer object
 * @provider: a #LassoProvider object
 *
 * Add @provider to the list of known providers object of @server.
 *
 * Return 0 if successful, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ otherwise.
 */
lasso_error_t
lasso_server_add_provider2(LassoServer *server, LassoProvider *provider)
{
	lasso_bad_param(SERVER, server);
	lasso_bad_param(PROVIDER, provider);
	g_return_val_if_fail(provider->ProviderID, LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT);
	g_return_val_if_fail(server->providers, LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT);

	g_hash_table_insert(server->providers, g_strdup(provider->ProviderID), provider);

	return 0;
}

/**
 * lasso_server_add_provider_from_buffer:
 * @server: a #LassoServer
 * @role: provider role, identity provider or service provider
 * @metadata: a string buffer containg the metadata file for a new provider
 * @public_key:(allow-none): provider public key file (may be a certificate) or NULL
 * @ca_cert_chain:(allow-none): provider CA certificate chain file or NULL
 *
 * Creates a new #LassoProvider and makes it known to the @server
 *
 * Return value: 0 on success; a negative value if an error occured.
 **/
gint
lasso_server_add_provider_from_buffer(LassoServer *server, LassoProviderRole role,
		const gchar *metadata, const gchar *public_key, const gchar *ca_cert_chain)
{
	return lasso_server_add_provider_helper(server, role, metadata,
			public_key, ca_cert_chain, lasso_provider_new_from_buffer);
}


/**
 * lasso_server_destroy:
 * @server: a #LassoServer
 *
 * Destroys a server.
 **/
void
lasso_server_destroy(LassoServer *server)
{
	lasso_node_destroy(LASSO_NODE(server));
}


/**
 * lasso_server_set_encryption_private_key:
 * @server: a #LassoServer
 * @filename_or_buffer:(allow-none): file name of the encryption key to load or its content as a
 * NULL-terminated string.
 *
 * Load an encryption private key from a file and set it in the server object
 *
 * If @filename_or_buffer is NULL, it frees the currently setted key.
 *
 * Return value: 0 on success; another value if an error occured.
 * Deprecated: 2.3: Use lasso_server_set_encryption_private_key_with_password() instead.
 **/
int
lasso_server_set_encryption_private_key(LassoServer *server, const gchar *filename_or_buffer)
{
	return lasso_server_set_encryption_private_key_with_password(server, filename_or_buffer,
			NULL);
}

/**
 * lasso_server_set_encryption_private_key_with_password:
 * @server: a #LassoServer
 * @filename_or_buffer:(allow-none): file name of the encryption key to load or its content as a
 * NULL-terminated string.
 * @password:(allow-none): an optional password to decrypt the encryption key.
 *
 * Load an encryption private key from a file and set it in the server object. If @password is
 * non-NULL try to decrypt the key with it.
 *
 * If @filename_or_buffer is NULL, it frees the currently setted key.
 *
 * Return value: 0 on success; another value if an error occured.
 * Since: 2.3
 **/
int
lasso_server_set_encryption_private_key_with_password(LassoServer *server,
		const gchar *filename_or_buffer, const gchar *password)
{
	if (filename_or_buffer) {
		xmlSecKey *key = lasso_xmlsec_load_private_key(filename_or_buffer, password,
				server->signature_method, NULL);
		if (! key || ! (xmlSecKeyGetType(key) & xmlSecKeyDataTypePrivate)) {
			return LASSO_SERVER_ERROR_SET_ENCRYPTION_PRIVATE_KEY_FAILED;
		}
		lasso_list_add_new_sec_key(server->private_data->encryption_private_keys, key);
	}

	return 0;
}

/**
 * lasso_server_load_affiliation:
 * @server: a #LassoServer
 * @filename: file name of the affiliation metadata to load
 *
 * Load an affiliation metadata file into @server; this must be called after
 * providers have been added to @server.
 *
 * Return value: 0 on success; another value if an error occured.
 **/
int
lasso_server_load_affiliation(LassoServer *server, const gchar *filename)
{
	LassoProvider *provider = LASSO_PROVIDER(server);
	xmlDoc *doc;
	xmlNode *node;
	int rc = 0;

	doc = lasso_xml_parse_file(filename);
	goto_cleanup_if_fail_with_rc (doc != NULL, LASSO_XML_ERROR_INVALID_FILE);

	node = xmlDocGetRootElement(doc);
	goto_cleanup_if_fail_with_rc (node != NULL && node->ns != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);

	if (provider->private_data->conformance == LASSO_PROTOCOL_SAML_2_0) {
		rc = lasso_saml20_server_load_affiliation(server, node);
	} else {
		/* affiliations are not supported in ID-FF 1.2 mode */
		rc = LASSO_ERROR_UNIMPLEMENTED;
	}
cleanup:
	lasso_release_doc(doc);
	return rc;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "PrivateKeyFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoServer, private_key), NULL,
		NULL, NULL},
	{ "PrivateKeyPassword", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoServer, private_key_password), NULL, NULL, NULL},
	{ "CertificateFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoServer, certificate), NULL,
		NULL, NULL},
	{ "SignatureMethod", SNIPPET_ATTRIBUTE, 0, NULL, NULL, NULL },
	{ "Providers", SNIPPET_LIST_NODES, 0, NULL, NULL, NULL },
	{ "ServerDumpVersion", SNIPPET_ATTRIBUTE, 0, NULL, NULL, NULL },
#ifdef LASSO_WSF_ENABLED
	{ "Services", SNIPPET_LIST_NODES, 0, NULL, NULL, NULL },
	{ "SvcMDs", SNIPPET_LIST_NODES, 0, NULL, NULL, NULL },
#endif

	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
add_provider_childnode(G_GNUC_UNUSED gchar *key, LassoProvider *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}


static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoServer *server = LASSO_SERVER(node);
	char *signature_methods[] = { NULL, RSA_SHA1, DSA_SHA1, HMAC_SHA1};
	xmlNode *xmlnode = NULL, *ret_xmlnode = NULL;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlSetProp(xmlnode, (xmlChar*)"ServerDumpVersion", (xmlChar*)"2");
	if (server->signature_method >= G_N_ELEMENTS(signature_methods))
		goto cleanup;
	xmlSetProp(xmlnode, (xmlChar*)"SignatureMethod",
			(xmlChar*)signature_methods[server->signature_method]);

	/* Providers */
	if (g_hash_table_size(server->providers)) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Providers", NULL);
		g_hash_table_foreach(server->providers,
				(GHFunc)add_provider_childnode, t);
	}

#ifdef LASSO_WSF_ENABLED
	lasso_server_dump_id_wsf_services(server, xmlnode);
	lasso_server_dump_id_wsf20_svcmds(server, xmlnode);
#endif

	xmlCleanNs(xmlnode);
	lasso_transfer_xml_node(ret_xmlnode, xmlnode);

cleanup:
	lasso_release_xml_node(xmlnode);
	return ret_xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoServer *server = LASSO_SERVER(node);
	xmlNode *t;
	xmlChar *s;
	int rc = 0;

	rc = parent_class->init_from_xml(node, xmlnode);

	if (server->private_key) {
		lasso_server_set_encryption_private_key_with_password(server, server->private_key,
				server->private_key_password);
	}
	if (rc)
		return rc;

	s = xmlGetProp(xmlnode, (xmlChar*)"SignatureMethod");
	if (lasso_strisequal((char*) s, RSA_SHA1))
		server->signature_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	else if (lasso_strisequal((char*) s, DSA_SHA1))
		server->signature_method = LASSO_SIGNATURE_METHOD_DSA_SHA1;
	else if (lasso_strisequal((char*) s, HMAC_SHA1))
		server->signature_method = LASSO_SIGNATURE_METHOD_HMAC_SHA1;
	else {
		warning("Unable to rebuild a LassoServer object from XML, bad SignatureMethod: %s",
			s);
		goto_cleanup_with_rc(LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED);
	}

	t = xmlSecGetNextElementNode(xmlnode->children);
	while (t) {
		/* Providers */
		if (strcmp((char*)t->name, "Providers") == 0) {
			xmlNode *t2 = xmlSecGetNextElementNode(t->children);

			while (t2) {
				LassoProvider *p;

				p = g_object_new(LASSO_TYPE_PROVIDER, NULL);
				lasso_check_good_rc(lasso_node_init_from_xml((LassoNode*)p,
							t2))
				if (lasso_provider_load_public_key(p, LASSO_PUBLIC_KEY_SIGNING)) {
					g_hash_table_insert(server->providers,
							g_strdup(p->ProviderID), p);
				} else {
					critical("Failed to load signing public key for %s.",
							p->ProviderID);
					lasso_release_gobject(p);
					goto_cleanup_with_rc(
						LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED);
				}
				t2 = xmlSecGetNextElementNode(t2->next);
			}
		}

#ifdef LASSO_WSF_ENABLED
		lasso_server_init_id_wsf_services(server, t);
		lasso_server_init_id_wsf20_svcmds(server, t);
#endif

		t = xmlSecGetNextElementNode(t->next);
	}

cleanup:
	lasso_release_xml_string(s);

	return 0;
}


static gboolean
get_first_providerID(gchar *key, G_GNUC_UNUSED gpointer value, char **providerID)
{
	*providerID = key;
	return TRUE;
}

static gboolean
get_first_providerID_by_role(G_GNUC_UNUSED gchar *key, gpointer value, LassoProviderRole role) {
	LassoProvider *provider = (LassoProvider*)value;
	if (provider->role == role || role == LASSO_PROVIDER_ROLE_ANY) {
		return TRUE;
	}
	return FALSE;
}

/**
 * lasso_server_get_first_providerID_by_role
 * @server: a #LassoServer
 * @role: the #LassoProviderRole of the researched provider
 *
 * Looks up and returns the provider ID of known provider with the given role.
 *
 * Return value: the provider ID, NULL if there are no providers. This string
 *     must be freed by the caller.
 */
gchar *
lasso_server_get_first_providerID_by_role(const LassoServer *server, LassoProviderRole role)
{
	LassoProvider *a_provider;
	a_provider = LASSO_PROVIDER(g_hash_table_find(server->providers,
		(GHRFunc) get_first_providerID_by_role,
		(gpointer)role));
	if (a_provider) {
		return g_strdup(a_provider->ProviderID);
	} else {
		return NULL;
	}
}

/**
 * lasso_server_get_first_providerID:
 * @server: a #LassoServer
 *
 * Looks up and returns the provider ID of a known provider
 *
 * Return value:(transfer full)(allow-none): the provider ID, NULL if there are no providers.  This
 * string must be freed by the caller.
 **/
gchar*
lasso_server_get_first_providerID(LassoServer *server)
{
	gchar *providerID = NULL;

	g_hash_table_find(server->providers, (GHRFunc)get_first_providerID, &providerID);
	return g_strdup(providerID);
}


/**
 * lasso_server_get_provider:
 * @server: a #LassoServer
 * @providerID: the provider ID
 *
 * Looks up for a #LassoProvider whose ID is @providerID and returns it.
 *
 * Return value: (transfer none): the #LassoProvider, NULL if it was not found.  The
 *     #LassoProvider is owned by Lasso and should not be freed.
 **/
LassoProvider*
lasso_server_get_provider(const LassoServer *server, const gchar *providerID)
{
	if (! LASSO_IS_SERVER(server) || providerID == NULL || strlen(providerID) == 0) {
		return NULL;
	}
	return g_hash_table_lookup(server->providers, providerID);
}


static gboolean
get_providerID_with_hash(gchar *key, G_GNUC_UNUSED gpointer value, char **providerID)
{
	char *hash = *providerID;
	xmlChar *hash_providerID;
	char *b64_hash_providerID;

	hash_providerID = (xmlChar*)lasso_sha1(key);
	b64_hash_providerID = (char*)xmlSecBase64Encode(hash_providerID, 20, 0);
	xmlFree(hash_providerID);

	if (strcmp(b64_hash_providerID, hash) == 0) {
		xmlFree(b64_hash_providerID);
		*providerID = key;
		return TRUE;
	}
	xmlFree(b64_hash_providerID);

	return FALSE;
}


/**
 * lasso_server_get_providerID_from_hash:
 * @server: a #LassoServer
 * @b64_hash: the base64-encoded provider ID hash
 *
 * Looks up a #LassoProvider whose ID hash is @b64_hash and returns its
 * provider ID.
 *
 * Return value:(transfer full)(allow-none): the provider ID, NULL if it was not found.
 **/
gchar*
lasso_server_get_providerID_from_hash(LassoServer *server, gchar *b64_hash)
{
	gchar *providerID = b64_hash; /* kludge */

	if (g_hash_table_find(server->providers, (GHRFunc)get_providerID_with_hash, &providerID))
		return g_strdup(providerID);
	return NULL;
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoServer *server = LASSO_SERVER(object);

	if (! server->private_data || server->private_data->dispose_has_run == TRUE) {
		return;
	}
	server->private_data->dispose_has_run = TRUE;

	lasso_release_list_of_sec_key(server->private_data->encryption_private_keys);

	lasso_release_list_of_gobjects(server->private_data->svc_metadatas);

	lasso_release_ghashtable(server->services);

	/* free allocated memory for hash tables */
	lasso_mem_debug("LassoServer", "Providers", server->providers);
	lasso_release_ghashtable(server->providers);

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(server));
}

static void
finalize(GObject *object)
{
	LassoServer *server = LASSO_SERVER(object);
	int i = 0;

	lasso_release(server->private_key);
	if (server->private_key_password) {
		/* don't use memset() because it may be optimised away by
		 * compiler (since the string is freed just after */
		while (server->private_key_password[i])
			server->private_key_password[i++] = 0;
		lasso_release(server->private_key_password);
	}
	lasso_release(server->certificate);
	lasso_release(server->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(server));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoServer *server)
{
	server->private_data = g_new0(LassoServerPrivate, 1);
	server->private_data->dispose_has_run = FALSE;
	server->private_data->encryption_private_keys = NULL;
	server->private_data->svc_metadatas = NULL;

	server->providers = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free,
			g_object_unref);

	server->private_key = NULL;
	server->private_key_password = NULL;
	server->certificate = NULL;
	server->signature_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;

	server->services = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			g_object_unref);
}

static void
class_init(LassoServerClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Server");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_server_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoServerClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoServer),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_PROVIDER,
				"LassoServer", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_server_new:
 * @metadata: path to the provider metadata file or NULL, for a LECP server
 * @private_key:(allow-none): path to the the server private key file or NULL
 * @private_key_password:(allow-none): password to private key if it is encrypted, or NULL
 * @certificate:(allow-none): path to the server certificate file, or NULL
 *
 * Creates a new #LassoServer.
 *
 * Return value: a newly created #LassoServer object; or NULL if an error
 *      occured
 **/
LassoServer*
lasso_server_new(const gchar *metadata,
		const gchar *private_key,
		const gchar *private_key_password,
		const gchar *certificate)
{
	LassoServer *server;

	server = g_object_new(LASSO_TYPE_SERVER, NULL);

	/* metadata can be NULL (if server is a LECP) */
	if (metadata != NULL) {
		if (lasso_provider_load_metadata(LASSO_PROVIDER(server), metadata) == FALSE) {
			message(G_LOG_LEVEL_CRITICAL,
					"Failed to load metadata from %s.", metadata);
			lasso_release_gobject(server);
			return NULL;
		}
	}

	lasso_assign_string(server->certificate, certificate);
	if (private_key) {
		lasso_assign_string(server->private_key, private_key);
		lasso_assign_string(server->private_key_password, private_key_password);
		if (lasso_server_set_encryption_private_key_with_password(server, private_key,
				private_key_password) != 0) {
			message(G_LOG_LEVEL_WARNING, "Cannot load the private key");
			lasso_release_gobject(server);
			return NULL;
		}
	}
	lasso_provider_load_public_key(&server->parent, LASSO_PUBLIC_KEY_SIGNING);
	lasso_provider_load_public_key(&server->parent, LASSO_PUBLIC_KEY_ENCRYPTION);

	return server;
}

/**
 * lasso_server_new_from_buffers:
 * @metadata: NULL terminated string containing the content of an ID-FF 1.2 metadata file
 * @private_key_content:(allow-none): NULL terminated string containing a PEM formatted private key
 * @private_key_password:(allow-none): a NULL terminated string which is the optional password of
 * the private key
 * @certificate_content:(allow-none): NULL terminated string containing a PEM formatted X509
 * certificate
 *
 * Creates a new #LassoServer.
 *
 * Return value: a newly created #LassoServer object; or NULL if an error occured
 */
LassoServer*
lasso_server_new_from_buffers(const char *metadata, const char *private_key_content, const char
		*private_key_password, const char *certificate_content)
{
	LassoServer *server;

	server = g_object_new(LASSO_TYPE_SERVER, NULL);
	/* metadata can be NULL (if server is a LECP) */
	if (metadata != NULL) {
		if (lasso_provider_load_metadata_from_buffer(LASSO_PROVIDER(server), metadata) == FALSE) {
			message(G_LOG_LEVEL_CRITICAL,
					"Failed to load metadata from preloaded buffer");
			lasso_release_gobject(server);
			return NULL;
		}
	}
	lasso_assign_string(server->certificate, certificate_content);
	if (private_key_content) {
		lasso_assign_string(server->private_key, private_key_content);
		lasso_assign_string(server->private_key_password, private_key_password);

		if (lasso_server_set_encryption_private_key_with_password(server, private_key_content,
				private_key_password) != 0) {
			message(G_LOG_LEVEL_WARNING, "Cannot load the private key");
			lasso_release_gobject(server);
			return NULL;
		}
	}
	lasso_provider_load_public_key(&server->parent, LASSO_PUBLIC_KEY_SIGNING);
	lasso_provider_load_public_key(&server->parent, LASSO_PUBLIC_KEY_ENCRYPTION);

	return server;
}
/**
 * lasso_server_new_from_dump:
 * @dump: XML server dump
 *
 * Restores the @dump to a new #LassoServer.
 *
 * Return value: a newly created #LassoServer; or NULL if an error occured
 **/
LassoServer*
lasso_server_new_from_dump(const gchar *dump)
{
	LassoServer *server;

	server = (LassoServer*)lasso_node_new_from_dump(dump);
	if (! LASSO_IS_SERVER(server)) {
		lasso_release_gobject(server);
	}
	return server;
}

/**
 * lasso_server_dump:
 * @server: a #LassoServer
 *
 * Dumps @server content to an XML string.
 *
 * Return value:(transfer full): the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_server_dump(LassoServer *server)
{
	return lasso_node_dump(LASSO_NODE(server));
}

/**
 * lasso_server_get_private_key:
 * @server: a #LassoServer object
 *
 * Return value:(transfer full): a newly created #xmlSecKey object.
 */
xmlSecKey*
lasso_server_get_private_key(LassoServer *server)
{
	if (! LASSO_IS_SERVER(server))
		return NULL;

	if (! server->private_key)
		return NULL;

	return lasso_xmlsec_load_private_key(server->private_key, server->private_key_password,
			server->signature_method, server->certificate);
}

/**
 * lasso_server_get_signature_context_for_provider:
 * @server: a #LassoServer object
 * @provider: a #LassoProvider object
 *
 * Find the key and signature method to sign messages adressed to @provider. If @provider has an
 * override over the private key of the @server object, use this override.
 *
 * The returned context content is now owned by the caller, if it must survives the @server or
 * @provider object life, the key should be copied.
 *
 * Return value: 0 if successful, an error code otherwise.
 *
 */
lasso_error_t
lasso_server_get_signature_context_for_provider(LassoServer *server,
		LassoProvider *provider, LassoSignatureContext *signature_context)
{
	lasso_error_t rc = 0;
	LassoSignatureContext *private_context = NULL;

	lasso_bad_param(SERVER, server);
	lasso_null_param(signature_context);

	if (provider) {
		lasso_bad_param(PROVIDER, provider);
		private_context = &provider->private_data->signature_context;
	}

	if (private_context && lasso_validate_signature_method(private_context->signature_method)) {
		lasso_assign_signature_context(*signature_context, *private_context);
	} else {
		rc = lasso_server_get_signature_context(server, signature_context);
	}

	return rc;

}

/**
 * lasso_server_get_signature_context:
 * @server: a #LassoServer object
 * @context: a pointer to an allocated and initialized #LassoSignatureContext structure
 *
 * Try to create a signature context for this server. Beware that you should better use
 * lasso_server_get_signature_context_for_provider() or
 * lasso_server_get_signature_context_for_provider_by_name() in mot of the case when you know the
 * target for your signature, because the provider could have special signature needs, like using a
 * shared secret signature.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
lasso_error_t
lasso_server_get_signature_context(LassoServer *server, LassoSignatureContext *context)
{
	lasso_bad_param(SERVER, server);
	lasso_null_param(context);

	lasso_assign_new_signature_context(*context,
			lasso_make_signature_context_from_path_or_string(
				server->private_key, server->private_key_password,
				server->signature_method, server->certificate));
	if (! lasso_validate_signature_context(*context)) {
		return LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED;
	}
	return 0;
}

/**
 * lasso_server_get_signature_context_for_provider_by_name:
 * @server: a #LassoServer object
 * @provider_id: the identifier of a known provider
 *
 * Find the key and signature method to sign messages adressed to @provider. If @provider has an
 * override over the private key of the @server object, use this override.
 *
 * The returned context content is now owned by the caller, if it must survives the @server or
 * provider object life, the key should be copied.
 *
 * Return value: 0 if successful, an error code otherwise.
 *
 */
lasso_error_t
lasso_server_get_signature_context_for_provider_by_name(LassoServer *server,
		const char *provider_id, LassoSignatureContext *signature_context)
{
	LassoProvider *provider;
	lasso_bad_param(SERVER, server);

	provider = lasso_server_get_provider(server, provider_id);
	return lasso_server_get_signature_context_for_provider(server,
			provider, signature_context);
}

/**
 * lasso_server_set_signature_for_provider_by_name:
 * @server: a #LassoServer object
 * @provider_id: the identifier of a known provider
 * @node: a #LassoNode object
 *
 * Return value: 0 if successful, an error code otherwise.
 */
lasso_error_t
lasso_server_set_signature_for_provider_by_name(LassoServer *server, const char *provider_id, LassoNode *node)
{
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;
	lasso_error_t rc = 0;

	lasso_check_good_rc(lasso_server_get_signature_context_for_provider_by_name(server,
				provider_id, &context));
	lasso_node_set_signature(node, context);
cleanup:
	return rc;
}

/**
 * lasso_server_export_to_query_for_provider_by_name:
 * @server: a #LassoServer object
 * @provider_id: the identifier of a known provider
 * @node: a #LassoNode object
 *
 * Return value: 0 if successful, an error code otherwise.
 */
lasso_error_t
lasso_server_export_to_query_for_provider_by_name(LassoServer *server, const char *provider_id, LassoNode *node, char **out)
{
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;
	lasso_error_t rc = 0;
	char *query = NULL;

	lasso_check_good_rc(lasso_server_get_signature_context_for_provider_by_name(server,
				provider_id, &context));
	query = lasso_node_build_query(node);
	goto_cleanup_if_fail_with_rc(query, LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
	if (lasso_validate_signature_method(context.signature_method)) {
		lasso_assign_new_string(query, lasso_query_sign(query, context));
	}
	goto_cleanup_if_fail_with_rc(query,
			LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED);
	lasso_assign_new_string(*out, query);
cleanup:
	lasso_assign_new_signature_context(context, LASSO_SIGNATURE_CONTEXT_NONE);
	return rc;
}

/**
 * lasso_server_get_encryption_private_keys:
 * @server: a #LassoServer object
 *
 * Return:(transfer none)(element-type xmlSecKeyPtr): a GList of xmlSecKey object, it is owned by the #LassoServer object, so do not
 * free it.
 */
GList*
lasso_server_get_encryption_private_keys(LassoServer *server)
{
	if (! LASSO_IS_SERVER(server))
		return NULL;

	if (! server->private_data)
		return NULL;

	return server->private_data->encryption_private_keys;
}

/**
 * lasso_server_load_metadata:
 * @server: a #LassoServer object
 * @role: a #LassoProviderRole value
 * @federation_file: path to a SAML 2.0 metadata file
 * @trusted_roots:(allow-none): a PEM encoded files containing the certificates to check signatures
 * on the metadata file (optional)
 * @blacklisted_entity_ids:(allow-none)(element-type string): a list of EntityID which should not be
 * loaded, can be NULL.
 * @loaded_entity_ids:(transfer full)(element-type string)(allow-none): an output parameter for the
 * list of the loaded EntityID, can be NULL.
 * @flags: flags modifying the behaviour for checking signatures on EntityDescriptor and
 * EntitiesDescriptors nodes.
 *
 * Load all the SAML 2.0 entities from @federation_file which contains a declaration for @role. If
 * @trusted_roots is non-NULL, use it to check a signature on the metadata file, otherwise ignore
 * signature validation.
 *
 * Return value: 0 on success, an error code otherwise, among:
 * <itemizedlist>
 * <listitem><para>
 * LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if server is not a #LassoServer object or @role is not a
 * valid role value,
 * </para></listitem>
 * <listitem><para>
 * LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED if the @trusted_root file cannot be loaded,
 * </listitem></para>
 * </itemizedlist>
 */
lasso_error_t
lasso_server_load_metadata(LassoServer *server, LassoProviderRole role, const gchar *federation_file,
		const gchar *trusted_roots, GList *blacklisted_entity_ids,
		GList **loaded_entity_ids, LassoServerLoadMetadataFlag flags)
{
	xmlDoc *doc = NULL;
	xmlNode *root = NULL;
	xmlSecKeysMngr *keys_mngr = NULL;
	lasso_error_t rc = 0;

	lasso_bad_param(SERVER, server);
	g_return_val_if_fail(role == LASSO_PROVIDER_ROLE_SP || role == LASSO_PROVIDER_ROLE_IDP,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (flags == LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT) {
		flags = LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITIES_DESCRIPTOR_SIGNATURE
			| LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITY_DESCRIPTOR_SIGNATURE
			| LASSO_SERVER_LOAD_METADATA_FLAG_INHERIT_SIGNATURE;
	}

	if (trusted_roots) {
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(trusted_roots);
		lasso_return_val_if_fail(keys_mngr != NULL,
				LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED);
	}
	doc = lasso_xml_parse_file(federation_file);
	goto_cleanup_if_fail_with_rc(doc, LASSO_SERVER_ERROR_INVALID_XML);
	root = xmlDocGetRootElement(doc);
	if (lasso_strisequal((char*)root->ns->href, LASSO_SAML2_METADATA_HREF)) {
		lasso_check_good_rc(lasso_saml20_server_load_metadata(server, role, doc, root,
					blacklisted_entity_ids, loaded_entity_ids, keys_mngr, flags));
	} else {
		goto_cleanup_with_rc(LASSO_ERROR_UNIMPLEMENTED);
	}

cleanup:
	lasso_release_key_manager(keys_mngr);
	lasso_release_doc(doc);
	return rc;
}
