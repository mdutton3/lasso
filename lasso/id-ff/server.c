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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * SECTION:server
 * @short_description: Representation of the current server
 *
 * It holds the data about a provider, other providers it knows, which
 * certificates to use, etc.
 **/

#include <xmlsec/base64.h>

#include <config.h>
#include <lasso/id-ff/server.h>

#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/serverprivate.h>

#include <lasso/saml-2.0/serverprivate.h>

#ifdef LASSO_WSF_ENABLED
#include <lasso/id-wsf-2.0/server.h>
#include <lasso/xml/id-wsf-2.0/disco_service_context.h>
#endif

#include "../utils.h"

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

	g_hash_table_insert(server->providers, g_strdup(provider->ProviderID), provider);

	return 0;
}

/**
 * lasso_server_add_provider:
 * @server: a #LassoServer
 * @role: provider role, identity provider or service provider
 * @metadata: path to the provider metadata file
 * @public_key: provider public key file (may be a certificate) or NULL
 * @ca_cert_chain: provider CA certificate chain file or NULL
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
 * lasso_server_add_provider_from_buffer:
 * @server: a #LassoServer
 * @role: provider role, identity provider or service provider
 * @metadata: a string buffer containg the metadata file for a new provider
 * @public_key: provider public key file (may be a certificate) or NULL
 * @ca_cert_chain: provider CA certificate chain file or NULL
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

#ifdef LASSO_WSF_ENABLED
/**
 * lasso_server_add_service:
 * @server: a #LassoServer
 * @service: a #LassoNode object implementing representing a service endpoint.
 *
 * Add a service to the registry of service of this #LassoServer object.
 *
 * Return value: 0 on success; a negative value if an error occured.
 **/
gint
lasso_server_add_service(LassoServer *server, LassoNode *service)
{
	g_return_val_if_fail(LASSO_IS_SERVER(server), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(service != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (LASSO_IS_DISCO_SERVICE_INSTANCE(service)) {
		g_hash_table_insert(server->services,
				g_strdup(LASSO_DISCO_SERVICE_INSTANCE(service)->ServiceType),
				g_object_ref(service));
	} else if (LASSO_IS_IDWSF2_DISCO_SVC_METADATA(service)) {
		return lasso_server_add_svc_metadata(server,
				LASSO_IDWSF2_DISCO_SVC_METADATA(service));
	} else {
		return LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ;
	}
	return 0;
}
#else
gint
lasso_server_add_service(G_GNUC_UNUSED LassoServer *server, G_GNUC_UNUSED LassoNode *service)
{
	return LASSO_ERROR_UNIMPLEMENTED;
}
#endif


/**
 * lasso_server_add_service_from_dump:
 * @server: a #LassoServer
 * @dump: the XML dump of a #LassoNode representing a service endpoint.
 *
 * An utility function that parse a #LassoNode dump an try to add it as a
 * service using lasso_server_add_service.
 *
 * Return value: 0 if succesfull, LASSO_PARAM_ERROR_BAD_TYPE_OF_NULL_OBJECT if
 * said dump is not a #LassoNode or is not of the righ type,
 * LASSO_PARAM_ERROR_INVALID_VALUE if dump is NULL.
 **/
gint
lasso_server_add_service_from_dump(LassoServer *server, const gchar *dump)
{
	LassoNode *node;
	gint return_code;

	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	node = lasso_node_new_from_dump(dump);

	return_code = lasso_server_add_service(server, node);

	g_object_unref(node);

	return return_code;
}

#ifdef LASSO_WSF_ENABLED
gint
lasso_server_add_svc_metadata(LassoServer *server, LassoIdWsf2DiscoSvcMetadata *metadata)
{

	g_return_val_if_fail(LASSO_IS_SERVER(server), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCO_SVC_METADATA(metadata),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	server->private_data->svc_metadatas = g_list_append(
		server->private_data->svc_metadatas, g_object_ref(metadata));

	return 0;
}

const GList *
lasso_server_get_svc_metadatas(LassoServer *server)
{
	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	return server->private_data->svc_metadatas;
}

/* XXX: return value must be freed by caller */
GList *
lasso_server_get_svc_metadatas_with_id_and_type(LassoServer *server, GList *svcMDIDs,
	const gchar *service_type)
{
	gchar *svcMDID;
	LassoIdWsf2DiscoSvcMetadata *md;
	GList *result = NULL;
	GList *i;
	GList *j;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);
	g_return_val_if_fail(service_type != NULL, NULL);

	for (i = g_list_first(server->private_data->svc_metadatas); i != NULL; i = g_list_next(i)) {
		md = LASSO_IDWSF2_DISCO_SVC_METADATA(i->data);
		/* FIXME: this assumes there is one and only one service
		 * context, and service type, this should be fixed to iterate
		 * properly on the GList */
		if (md->ServiceContext == NULL || strcmp((char*)(LASSO_IDWSF2_DISCO_SERVICE_CONTEXT(
				md->ServiceContext->data)->ServiceType)->data, service_type) != 0) {
			continue;
		}
		if (svcMDIDs == NULL) {
			/* If no svcMDID is given, return all the metadatas with given */
			/* service type */
			result = g_list_append(result, g_object_ref(md));
		} else {
			for (j = g_list_first(svcMDIDs); j != NULL; j = g_list_next(j)) {
				svcMDID = (gchar *)(j->data);
				if (strcmp(svcMDID, md->svcMDID) == 0) {
					result = g_list_append(result, g_object_ref(md));
				}
			}
		}
	}

	return result;
}
#endif


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
 * @filename: file name of the encryption key to load
 *
 * Load an encryption private key from a file and set it in the server object
 *
 * Return value: 0 on success; another value if an error occured.
 **/
int
lasso_server_set_encryption_private_key(LassoServer *server, const gchar *filename)
{
	LassoPemFileType file_type;

	if (server->private_data->encryption_private_key != NULL) {
		xmlSecKeyDestroy(server->private_data->encryption_private_key);
		server->private_data->encryption_private_key = NULL;
	}
	file_type = lasso_get_pem_file_type(filename);
	if (file_type == LASSO_PEM_FILE_TYPE_PRIVATE_KEY) {
		server->private_data->encryption_private_key = xmlSecCryptoAppKeyLoad(filename,
			xmlSecKeyDataFormatPem, NULL, NULL, NULL);
	}

	if (server->private_data->encryption_private_key == NULL)
		return LASSO_SERVER_ERROR_SET_ENCRYPTION_PRIVATE_KEY_FAILED;

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

	doc = xmlParseFile(filename);
	goto_exit_if_fail (doc != NULL, LASSO_XML_ERROR_INVALID_FILE);

	node = xmlDocGetRootElement(doc);
	goto_exit_if_fail (node != NULL && node->ns != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);

	if (provider->private_data->conformance == LASSO_PROTOCOL_SAML_2_0) {
		rc = lasso_saml20_server_load_affiliation(server, node);
	} else {
		/* affiliations are not supported in ID-FF 1.2 mode */
		rc = LASSO_ERROR_UNIMPLEMENTED;
	}
exit:
	lasso_release_doc(doc);
	return rc;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "PrivateKeyFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoServer, private_key), NULL, NULL, NULL},
	{ "PrivateKeyPassword", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoServer, private_key_password), NULL, NULL, NULL},
	{ "CertificateFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoServer, certificate), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
add_provider_childnode(G_GNUC_UNUSED gchar *key, LassoProvider *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

#ifdef LASSO_WSF_ENABLED
static void
add_service_childnode(G_GNUC_UNUSED gchar *key, LassoNode *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

static void
add_childnode_from_list(LassoNode *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}
#endif

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoServer *server = LASSO_SERVER(node);
	char *signature_methods[] = { NULL, "RSA_SHA1", "DSA_SHA1"};
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlSetProp(xmlnode, (xmlChar*)"ServerDumpVersion", (xmlChar*)"2");
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
	/* Services */
	if (g_hash_table_size(server->services)) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Services", NULL);
		g_hash_table_foreach(server->services,
				(GHFunc)add_service_childnode, t);
	}

	/* Service Metadatas (SvcMD) */
	if (server->private_data->svc_metadatas != NULL) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"SvcMDs", NULL);
		g_list_foreach(server->private_data->svc_metadatas,
				(GFunc)add_childnode_from_list, t);
	}
#endif

	xmlCleanNs(xmlnode);

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoServer *server = LASSO_SERVER(node);
	xmlNode *t;
	xmlChar *s;
	int rc = 0;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc)
		return rc;

	s = xmlGetProp(xmlnode, (xmlChar*)"SignatureMethod");
	if (s && strcmp((char*)s, "RSA_SHA1") == 0)
		server->signature_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	if (s && strcmp((char*)s, "DSA_SHA1") == 0)
		server->signature_method = LASSO_SIGNATURE_METHOD_DSA_SHA1;
	if (s)
		xmlFree(s);

	t = xmlnode->children;
	while (t) {
		xmlNode *t2 = t->children;

		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		/* Providers */
		if (strcmp((char*)t->name, "Providers") == 0) {
			while (t2) {
				LassoProvider *p;
				if (t2->type != XML_ELEMENT_NODE) {
					t2 = t2->next;
					continue;
				}
				p = g_object_new(LASSO_TYPE_PROVIDER, NULL);
				LASSO_NODE_GET_CLASS(p)->init_from_xml(LASSO_NODE(p), t2);
				if (lasso_provider_load_public_key(p, LASSO_PUBLIC_KEY_SIGNING)) {
					g_hash_table_insert(server->providers,
							g_strdup(p->ProviderID), p);
				} else {
					message(G_LOG_LEVEL_CRITICAL,
							"Failed to load signing public key for %s.",
							p->ProviderID);
				}
				t2 = t2->next;
			}
		}

#ifdef LASSO_WSF_ENABLED
		/* Services */
		if (strcmp((char*)t->name, "Services") == 0) {
			while (t2) {
				LassoDiscoServiceInstance *s;
				if (t2->type != XML_ELEMENT_NODE) {
					t2 = t2->next;
					continue;
				}
				s = g_object_new(LASSO_TYPE_DISCO_SERVICE_INSTANCE, NULL);
				LASSO_NODE_GET_CLASS(s)->init_from_xml(LASSO_NODE(s), t2);
				g_hash_table_insert(server->services, g_strdup(s->ServiceType), s);
				t2 = t2->next;
			}
		}

		/* Service Metadatas (SvcMD) */
		if (strcmp((char*)t->name, "SvcMDs") == 0) {
			while (t2) {
				LassoIdWsf2DiscoSvcMetadata *svcMD;
				if (t2->type != XML_ELEMENT_NODE) {
					t2 = t2->next;
					continue;
				}
				svcMD = lasso_idwsf2_disco_svc_metadata_new();
				LASSO_NODE_GET_CLASS(svcMD)->init_from_xml(LASSO_NODE(svcMD), t2);
				server->private_data->svc_metadatas = g_list_append(
					server->private_data->svc_metadatas, svcMD);
				t2 = t2->next;
			}
		}
#endif

		t = t->next;
	}

	return 0;
}


static gboolean
get_first_providerID(gchar *key, G_GNUC_UNUSED gpointer value, char **providerID)
{
	*providerID = key;
	return TRUE;
}

/**
 * lasso_server_get_first_providerID:
 * @server: a #LassoServer
 *
 * Looks up and returns the provider ID of a known provider
 *
 * Return value: the provider ID, NULL if there are no providers.  This string
 *      must be freed by the caller.
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
 * Return value: the #LassoProvider, NULL if it was not found.  The
 *     #LassoProvider is owned by Lasso and should not be freed.
 **/
LassoProvider*
lasso_server_get_provider(LassoServer *server, const gchar *providerID)
{
	return g_hash_table_lookup(server->providers, providerID);
}


/**
 * lasso_server_get_service:
 * @server: a #LassoServer
 * @serviceType:
 *
 * ...
 *
 * Return value: the #LassoDiscoServiceInstance, NULL if it was not found.
 *     The #LassoDiscoServiceInstance is owned by Lasso and should not be
 *     freed.
 **/
LassoDiscoServiceInstance*
lasso_server_get_service(LassoServer *server, const gchar *serviceType)
{
	return g_hash_table_lookup(server->services, serviceType);
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
 * Return value: the provider ID, NULL if it was not found.
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

	if (server->private_data->dispose_has_run == TRUE) {
		return;
	}
	server->private_data->dispose_has_run = TRUE;

	/* FIXME : Probably necessary, must be tested */
/* 	if (server->private_data->encryption_private_key != NULL) { */
/* 		xmlSecKeyDestroy(server->private_data->encryption_private_key); */
/* 		server->private_data->encryption_private_key = NULL; */
/* 	} */

	if (server->private_data->svc_metadatas != NULL) {
		g_list_foreach(server->private_data->svc_metadatas, (GFunc)g_object_unref, NULL);
		g_list_free(server->private_data->svc_metadatas);
		server->private_data->svc_metadatas = NULL;
	}

	/* free allocated memory for hash tables */
	g_hash_table_destroy(server->providers);
	server->providers = NULL;

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(server));
}

static void
finalize(GObject *object)
{
	LassoServer *server = LASSO_SERVER(object);
	int i = 0;

	g_free(server->private_key);
	if (server->private_key_password) {
		/* don't use memset() because it may be optimised away by
		 * compiler (since the string is freeed just after */
		while (server->private_key_password[i])
			server->private_key_password[i++] = 0;
		g_free(server->private_key_password);
	}
	g_free(server->certificate);
	g_free(server->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(server));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoServer *server)
{
	server->private_data = g_new(LassoServerPrivate, 1);
	server->private_data->dispose_has_run = FALSE;
	server->private_data->encryption_private_key = NULL;
	server->private_data->svc_metadatas = NULL;

	server->providers = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free,
			(GDestroyNotify)lasso_node_destroy);

	server->private_key = NULL;
	server->private_key_password = NULL;
	server->certificate = NULL;
	server->signature_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;

	server->services = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_node_destroy);
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
 * @private_key: path to the the server private key file or NULL
 * @private_key_password: password to private key if it is encrypted, or NULL
 * @certificate: path to the server certificate file, or NULL
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
			lasso_node_destroy(LASSO_NODE(server));
			return NULL;
		}
	}

	server->private_key = g_strdup(private_key);
	server->private_key_password = g_strdup(private_key_password);
	server->certificate = g_strdup(certificate);

	return server;
}

/**
 * lasso_server_new_from_buffers:
 * @metadata: NULL terminated string containing the content of an ID-FF 1.2 metadata file
 * @privatekey: NULL terminated string containing a PEM formatted private key
 * @private_key_password: a NULL terminated string which is the optional password of the private key
 * @certificate: NULL terminated string containing a PEM formatted X509 certificate
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
			lasso_node_destroy(LASSO_NODE(server));
			return NULL;
		}
	}
	lasso_assign_string(server->private_key, private_key_content);
	lasso_assign_string(server->private_key_password, private_key_password);
	lasso_assign_string(server->certificate, certificate_content);

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
	LassoNode *server;
	server = lasso_node_new_from_dump(dump);
	if (server == NULL)
		return NULL;

	if (LASSO_IS_SERVER(server) == FALSE) {
		lasso_node_destroy(LASSO_NODE(server));
		return NULL;
	}
	return LASSO_SERVER(server);
}

/**
 * lasso_server_dump:
 * @server: a #LassoServer
 *
 * Dumps @server content to an XML string.
 *
 * Return value: the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_server_dump(LassoServer *server)
{
	return lasso_node_dump(LASSO_NODE(server));
}
