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

#include <xmlsec/base64.h>
#include <lasso/id-ff/server.h>

struct _LassoServerPrivate
{
	gboolean dispose_has_run;
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_server_add_provider:
 * @server: a LassoServer
 * @metadata: the provider metadata file
 * @public_key: the provider public key file (may be a certificate) or NULL
 * @ca_cert_chain: the provider CA certificate chain file or NULL
 * 
 * Adds a provider in a server.
 * 
 * Return value: 0 on success or a negative value if an error occurs.
 **/
gint
lasso_server_add_provider(LassoServer *server, LassoProviderRole role,
		gchar *metadata, gchar *public_key, gchar *ca_cert_chain)
{
	LassoProvider *provider;

	g_return_val_if_fail(LASSO_IS_SERVER(server), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(metadata != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	provider = lasso_provider_new(role, metadata, public_key, ca_cert_chain);
	if (provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to add new provider.");
		return LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED;
	}

	g_hash_table_insert(server->providers, g_strdup(provider->ProviderID), provider);

	return 0;
}

gchar*
lasso_server_get_authnRequestsSigned(LassoServer *server, GError     **err)
{
	/* XXX to do differently (add a boolean to struct) */
	g_assert_not_reached();
	return NULL;
}


void
lasso_server_destroy(LassoServer *server)
{
	g_object_unref(G_OBJECT(server));
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void add_provider_childnode(gchar *key, LassoProvider *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value)));
}

static xmlNode*
get_xmlNode(LassoNode *node)
{
	LassoServer *server = LASSO_SERVER(node);
	char *signature_methods[] = { NULL, "RSA_SHA1", "DSA_SHA1"};
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "Server");
	xmlSetProp(xmlnode, "ServerDumpVersion", "2");

	if (server->private_key && server->private_key[0])
		xmlNewTextChild(xmlnode, NULL, "PrivateKeyFilePath", server->private_key);
	if (server->secret_key && server->secret_key[0])
		xmlNewTextChild(xmlnode, NULL, "SecretKey", server->secret_key);
	if (server->certificate && server->certificate[0])
		xmlNewTextChild(xmlnode, NULL, "CertificateFilePath", server->certificate);
	xmlSetProp(xmlnode, "SignatureMethod", signature_methods[server->signature_method]);

	if (g_hash_table_size(server->providers)) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, "Providers", NULL);
		g_hash_table_foreach(server->providers,
				(GHFunc)add_provider_childnode, t);
	}

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoServer *server = LASSO_SERVER(node);
	xmlNode *t;
	xmlChar *s;
	int rc;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc)
		return rc;

	s = xmlGetProp(xmlnode, "SignatureMethod");
	if (s && strcmp(s, "RSA_SHA1") == 0)
		server->signature_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (s && strcmp(s, "DSA_SHA1") == 0)
		server->signature_method = LASSO_SIGNATURE_METHOD_DSA_SHA1;
	if (s)
		xmlFree(s);

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "PrivateKeyFilePath") == 0)
			server->private_key = xmlNodeGetContent(t);
		if (strcmp(t->name, "SecretKey") == 0)
			server->secret_key = xmlNodeGetContent(t);
		if (strcmp(t->name, "CertificateFilePath") == 0)
			server->certificate = xmlNodeGetContent(t);
		if (strcmp(t->name, "Providers") == 0) {
			xmlNode *t2 = t->children;
			LassoProvider *p;
			while (t2) {
				if (t2->type != XML_ELEMENT_NODE) {
					t2 = t2->next;
					continue;
				}
				p = g_object_new(LASSO_TYPE_PROVIDER, NULL);
				LASSO_NODE_GET_CLASS(p)->init_from_xml(LASSO_NODE(p), t2);
				g_hash_table_insert(server->providers,
						g_strdup(p->ProviderID), p);
				t2 = t2->next;
			}
		}
		t = t->next;
	}
	return 0;
}



static gboolean
get_first_providerID(gchar *key, gpointer value, char **providerID)
{
	*providerID = key;
	return TRUE;
}

gchar*
lasso_server_get_first_providerID(LassoServer *server)
{
	gchar *providerID = NULL;

	g_hash_table_find(server->providers, (GHRFunc)get_first_providerID, &providerID);
	return g_strdup(providerID);
}

LassoProvider*
lasso_server_get_provider(LassoServer *server, gchar *providerID)
{
	return g_hash_table_lookup(server->providers, providerID);
}


static gboolean
get_providerID_with_hash(gchar *key, gpointer value, char **providerID)
{
	char *hash = *providerID;
	char *hash_providerID, *b64_hash_providerID;

	hash_providerID = lasso_sha1(key);
	b64_hash_providerID = xmlSecBase64Encode(hash_providerID, 20, 0);
	xmlFree(hash_providerID);

	if (strcmp(b64_hash_providerID, hash) == 0) {
		xmlFree(b64_hash_providerID);
		*providerID = key;
		return TRUE;
	}
	xmlFree(b64_hash_providerID);

	return FALSE;
}


gchar*
lasso_server_get_providerID_from_hash(LassoServer *server, gchar *b64_hash)
{
	gchar *providerID = b64_hash; /* kludge */

	g_hash_table_find(server->providers, (GHRFunc)get_providerID_with_hash, &providerID);
	return g_strdup(providerID);
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoServer *server = LASSO_SERVER(object);

	if (server->private->dispose_has_run == TRUE) {
		return;
	}
	server->private->dispose_has_run = TRUE;

	debug("Server object 0x%x disposed ...", server);

	/* free allocated memory for providers array */
	/* XXX */

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(server));
}

static void
finalize(GObject *object)
{
	LassoServer *server = LASSO_SERVER(object);

	debug("Server object 0x%x finalized ...", server);

	g_free(server->private_key);
	g_free(server->secret_key);
	g_free(server->certificate);

	g_free(server->private);

	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(server));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoServer *server)
{
	server->private = g_new(LassoServerPrivate, 1);
	server->private->dispose_has_run = FALSE;

	server->providers = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free,
			(GDestroyNotify)lasso_node_destroy);
	server->private_key = NULL;
	server->secret_key = NULL;
	server->certificate = NULL;
	server->signature_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
}

static void
class_init(LassoServerClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

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
		};

		this_type = g_type_register_static(LASSO_TYPE_PROVIDER,
				"LassoServer", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_server_new:
 * @metadata: the server metadata file
 * @private_key: the server private key or NULL
 * @secret_key: the server secret key (to decrypt the private key)
 * @certificate: the server certificate
 * 
 * Creates a server. The caller is responsible for destroying returned
 * object by calling #lasso_server_destroy method.
 * 
 * Return value: a newly allocated #LassoServer object or NULL if an error occurs.
 **/
LassoServer*
lasso_server_new(const gchar *metadata,
		 const gchar *private_key,
		 const gchar *secret_key,
		 const gchar *certificate)
{
	LassoServer *server;

	server = g_object_new(LASSO_TYPE_SERVER, NULL);

	/* metadata can be NULL (if server is a LECP) */
	if (metadata != NULL) {
		lasso_provider_load_metadata(LASSO_PROVIDER(server), metadata);
		/* XXX: error checking */
	}

	server->private_key = g_strdup(private_key);
	server->secret_key = g_strdup(secret_key);
	server->certificate = g_strdup(certificate);

	return server;
}

LassoServer*
lasso_server_new_from_dump(const gchar *dump)
{
	LassoNode *server;
	server = lasso_node_new_from_dump(dump);
	if (server == NULL)
		return NULL;

	if (LASSO_IS_SERVER(server) == FALSE) {
		g_object_unref(server);
		return NULL;
	}
	return LASSO_SERVER(server);
}

gchar*
lasso_server_dump(LassoServer *server)
{
	return lasso_node_dump(LASSO_NODE(server), NULL, 1);
}

