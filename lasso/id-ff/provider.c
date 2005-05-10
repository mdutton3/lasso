/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/base64.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>

#include <lasso/id-ff/provider.h>
#include <lasso/id-ff/providerprivate.h>

struct _LassoProviderPrivate
{
	gboolean dispose_has_run;
	LibertyConformanceLevel conformance;
	GHashTable *SPDescriptor;
	char *default_assertion_consumer;
	GHashTable *IDPDescriptor;
	xmlNode *organization;
	xmlSecKey *public_key;
};

static char *protocol_uris[] = {
	"http://projectliberty.org/profiles/fedterm",
	"http://projectliberty.org/profiles/nim",
	"http://projectliberty.org/profiles/rni",
	"http://projectliberty.org/profiles/slo",
	NULL /* none for single sign on */
};
static char *protocol_md_nodename[] = {
	"FederationTerminationNotificationProtocolProfile",
	"NameIdentifierMappingProtocolProfile",
	"RegisterNameIdentifierProtocolProfile",
	"SingleLogoutProtocolProfile",
	"SingleSignOnProtocolProfile"
};
static char *protocol_roles[] = { NULL, "sp", "idp"};
char *protocol_methods[] = {"", "", "", "", "", "-http", "-soap"};

/*****************************************************************************/
/* public methods */
/*****************************************************************************/

/**
 * lasso_provider_get_assertion_consumer_service_url:
 * @provider: a #LassoProvider
 * @service_id: the AssertionConsumerServiceID, NULL for default
 *
 * Extracts the AssertionConsumerServiceURL from the provider metadata
 * descriptor.
 *
 * Return value: the element value, NULL if the element was not found.  This
 *      string must be freed by the caller.
 **/
gchar*
lasso_provider_get_assertion_consumer_service_url(LassoProvider *provider, const char *service_id)
{
	GHashTable *descriptor;
	GList *l;
	char *sid = (char*)service_id;
	char *name;

	if (sid == NULL)
		sid = provider->private_data->default_assertion_consumer;

	descriptor = provider->private_data->SPDescriptor;
	if (descriptor == NULL)
		return NULL;

	name = g_strdup_printf("AssertionConsumerServiceURL %s", sid);
	l = g_hash_table_lookup(descriptor, name);
	g_free(name);
	if (l == NULL)
		return NULL;

	return g_strdup(l->data);
}

/**
 * lasso_provider_get_metadata_one:
 * @provider: a #LassoProvider
 * @name: the element name
 *
 * Extracts the element @name from the provider metadata descriptor.
 *
 * Return value: the element value, NULL if the element was not found.  This
 *      string must be freed by the caller.
 **/
gchar*
lasso_provider_get_metadata_one(LassoProvider *provider, const char *name)
{
	GList *l;
	GHashTable *descriptor;

	descriptor = provider->private_data->SPDescriptor; /* default to SP */
	if (provider->role == LASSO_PROVIDER_ROLE_IDP)
		descriptor = provider->private_data->IDPDescriptor;
	if (descriptor == NULL)
		return NULL;

	l = g_hash_table_lookup(descriptor, name);
	if (l)
		return g_strdup(l->data);

	return NULL;
}


/**
 * lasso_provider_get_metadata_list:
 * @provider: a #LassoProvider
 * @name: the element name
 *
 * Extracts zero to many elements from the provider metadata descriptor.
 *
 * Return value: a #GList with the elements.  This GList is internally
 *      allocated and points to internally allocated strings.  It must
 *      not be freed, modified or stored.
 **/
GList*
lasso_provider_get_metadata_list(LassoProvider *provider, const char *name)
{
	GHashTable *descriptor;

	descriptor = provider->private_data->SPDescriptor; /* default to SP */
	if (provider->role == LASSO_PROVIDER_ROLE_IDP)
		descriptor = provider->private_data->IDPDescriptor;

	return g_hash_table_lookup(descriptor, name);
}


/**
 * lasso_provider_get_first_http_method:
 * @provider: a #LassoProvider
 * @remote_provider: a #LassoProvider depicting the remote provider
 * @protocol_type: a Liberty profile
 *
 * Looks up and returns a #LassoHttpMethod appropriate for performing the
 * @protocol_type between @provider and @remote_provider.
 *
 * Return value: the #LassoHttpMethod
 **/
LassoHttpMethod lasso_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type)
{
	char *protocol_profile_prefix;
	GList *local_supported_profiles;
	GList *remote_supported_profiles;
	GList *t1, *t2 = NULL;
	gboolean found;

	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP)
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP)
		provider->role = LASSO_PROVIDER_ROLE_SP;

	protocol_profile_prefix = g_strdup_printf("%s-%s",
			protocol_uris[protocol_type], protocol_roles[provider->role]);

	local_supported_profiles = lasso_provider_get_metadata_list(
			provider, protocol_md_nodename[protocol_type]);
	remote_supported_profiles = lasso_provider_get_metadata_list(
			remote_provider, protocol_md_nodename[protocol_type]);

	found = FALSE;
	t1 = local_supported_profiles;
	while (t1 && !found) {
		if (g_str_has_prefix(t1->data, protocol_profile_prefix)) {
			t2 = remote_supported_profiles;
			while (t2 && !found) {
				if (strcmp(t1->data, t2->data) == 0) {
					found = TRUE;
					break; /* avoid the g_list_next */
				}
				t2 = g_list_next(t2);
			}
		}
		t1 = g_list_next(t1);
	}
	g_free(protocol_profile_prefix);

	if (found) {
		if (g_str_has_suffix(t2->data, "http"))
			return LASSO_HTTP_METHOD_REDIRECT;
		if (t2 && g_str_has_suffix(t2->data, "soap"))
			return LASSO_HTTP_METHOD_SOAP;
		g_assert_not_reached();
	}

	return LASSO_HTTP_METHOD_NONE;
}

/**
 * lasso_provider_accept_http_method:
 * @provider: a #LassoProvider
 * @remote_provider: a #LassoProvider depicting the remote provider
 * @protocol_type: a Liberty profile type
 * @http_method: an HTTP method
 * @initiate_profile: whether @provider initiates the profile
 *
 * Gets if @http_method is an appropriate method for the @protocol_type profile
 * between @provider and @remote_provider.
 *
 * Return value: %TRUE if it is appropriate
 **/
gboolean
lasso_provider_accept_http_method(LassoProvider *provider, LassoProvider *remote_provider,
		LassoMdProtocolType protocol_type, LassoHttpMethod http_method,
		gboolean initiate_profile)
{ 
	LassoProviderRole initiating_role;
	char *protocol_profile;

	initiating_role = remote_provider->role;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		provider->role = LASSO_PROVIDER_ROLE_SP;
	}
	if (initiate_profile)
		initiating_role = provider->role;

	protocol_profile = g_strdup_printf("%s-%s%s",
			protocol_uris[protocol_type],
			protocol_roles[initiating_role],
			protocol_methods[http_method+1]);

	if (lasso_provider_has_protocol_profile(provider,
				protocol_type, protocol_profile) == FALSE)
		return FALSE;

	if (lasso_provider_has_protocol_profile(remote_provider,
				protocol_type, protocol_profile) == FALSE)
		return FALSE;

	return TRUE;
}

/**
 * lasso_provider_has_protocol_profile:
 * @provider: a #LassoProvider
 * @protocol_type: a Liberty profile type
 * @protocol_profile: a fully-qualified Liberty profile
 *
 * Gets if @provider supports @protocol_profile.
 *
 * Return value: %TRUE if it is supported
 **/
gboolean
lasso_provider_has_protocol_profile(LassoProvider *provider,
		LassoMdProtocolType protocol_type, const char *protocol_profile)
{
	GList *supported;
	
	supported = lasso_provider_get_metadata_list(
			provider, protocol_md_nodename[protocol_type]);
	
	if (g_list_find_custom(supported, protocol_profile, (GCompareFunc)strcmp) == NULL)
		return FALSE;
	return TRUE;
}

/**
 * lasso_provider_get_base64_succinct_id:
 * @provider: a #LassoProvider
 *
 * Computes and returns the base64-encoded provider succinct ID.
 *
 * Return value: the provider succinct ID.  This string must be freed by the
 *      caller.
 **/
char*
lasso_provider_get_base64_succinct_id(LassoProvider *provider)
{
	char *succinct_id, *base64_succinct_id;

	succinct_id = lasso_sha1(provider->ProviderID);
	base64_succinct_id = xmlSecBase64Encode(succinct_id, 20, 0);
	xmlFree(succinct_id);
	return base64_succinct_id;
}


/**
 * lasso_provider_get_organization
 * @provider: a #LassoProvider
 *
 * Returns the provider metadata <Organization> XML node.
 *
 * Return value: the <Organization/> node (libxml2 xmlNode*); or NULL if it is
 *      not found.  This xmlnode must be freed by the caller.
 **/
xmlNode*
lasso_provider_get_organization(LassoProvider *provider)
{
	if (provider->private_data->organization) {
		return xmlCopyNode(provider->private_data->organization, 1);
	} else {
		return NULL;
	}
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "PublicKeyFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProvider, public_key) },
	{ "CaCertChainFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProvider, ca_cert_chain) },
	{ "MetadataFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProvider, metadata_filename) },
	{ "ProviderID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoProvider, ProviderID) },
	{ NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static void
load_descriptor(xmlNode *xmlnode, GHashTable *descriptor, LassoProvider *provider)
{
	xmlNode *t;
	GList *elements;
	char *name;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "AssertionConsumerServiceURL") == 0) {
			char *isDefault = xmlGetProp(t, "isDefault");
			char *id = xmlGetProp(t, "id");
			name = g_strdup_printf("%s %s", t->name, id);
			if (isDefault) {
				if (strcmp(isDefault, "true") == 0 || strcmp(isDefault, "1") == 0)
					provider->private_data->default_assertion_consumer =
						g_strdup(id);
				xmlFree(isDefault);
			}
			xmlFree(id);
		} else {
			name = g_strdup(t->name);
		}
		elements = g_hash_table_lookup(descriptor, name);
		elements = g_list_append(elements, g_strdup(xmlNodeGetContent(t)));
		g_hash_table_insert(descriptor, name, elements);
		t = t->next;
	}
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoProvider *provider = LASSO_PROVIDER(node);
	char *roles[] = { "None", "SP", "IdP"};

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlSetProp(xmlnode, "ProviderDumpVersion", "2");
	if (provider->role)
		xmlSetProp(xmlnode, "ProviderRole", roles[provider->role]);

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoProvider *provider = LASSO_PROVIDER(node);
	xmlChar *s;

	parent_class->init_from_xml(node, xmlnode);
	
	if (xmlnode == NULL)
		return LASSO_ERROR_UNDEFINED;

	s = xmlGetProp(xmlnode, "ProviderRole");
	if (s && strcmp(s, "SP") == 0)
		provider->role = LASSO_PROVIDER_ROLE_SP;
	if (s && strcmp(s, "IdP") == 0)
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	if (s)
		xmlFree(s);

	if (provider->metadata_filename)
		lasso_provider_load_metadata(provider, provider->metadata_filename);

	return 0;
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
free_string(char *string)
{
	g_free(string);
}

static void
free_list_strings(gchar *key, GList *list, gpointer data)
{
	g_list_foreach(list, (GFunc)free_string, NULL);
	g_list_free(list);
}

static void
dispose(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

	if (provider->private_data->dispose_has_run) {
		return;
	}
	provider->private_data->dispose_has_run = TRUE;

	if (provider->private_data->IDPDescriptor) {
		g_hash_table_foreach(provider->private_data->IDPDescriptor,
				(GHFunc)free_list_strings, NULL);
		g_hash_table_destroy(provider->private_data->IDPDescriptor);
	}
	provider->private_data->IDPDescriptor = NULL;

	if (provider->private_data->SPDescriptor) {
		g_hash_table_foreach(provider->private_data->SPDescriptor,
				(GHFunc)free_list_strings, NULL);
		g_hash_table_destroy(provider->private_data->SPDescriptor);
	}
	provider->private_data->SPDescriptor = NULL;

	if (provider->private_data->organization) {
		xmlFreeNode(provider->private_data->organization);
		provider->private_data->organization = NULL;
	}

	if (provider->private_data->default_assertion_consumer) {
		g_free(provider->private_data->default_assertion_consumer);
		provider->private_data->default_assertion_consumer = NULL;
	}

	if (provider->private_data->public_key) {
		xmlSecKeyDestroy(provider->private_data->public_key);
		provider->private_data->public_key = NULL;
	}

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(provider));
}

static void
finalize(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

	g_free(provider->public_key);
	provider->public_key = NULL;
	g_free(provider->ca_cert_chain);
	provider->ca_cert_chain = NULL;
	g_free(provider->private_data);
	provider->private_data = NULL;

	G_OBJECT_CLASS(parent_class)->finalize(G_OBJECT(provider));
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/


static void
instance_init(LassoProvider *provider)
{
	provider->role = LASSO_PROVIDER_ROLE_NONE;
	provider->ProviderID = NULL;
	provider->metadata_filename = NULL;
	provider->public_key = NULL;
	provider->ca_cert_chain = NULL;
	provider->private_data = g_new(LassoProviderPrivate, 1);
	provider->private_data->dispose_has_run = FALSE;
	provider->private_data->default_assertion_consumer = NULL;
	provider->private_data->organization = NULL;
	provider->private_data->public_key = NULL;

	/* no value_destroy_func since it shouldn't destroy the GList on insert */
	provider->private_data->IDPDescriptor = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);
	provider->private_data->SPDescriptor = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);
}

static void
class_init(LassoProviderClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Provider");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_provider_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoProviderClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoProvider),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoProvider", &this_info, 0);
	}
	return this_type;
}

LibertyConformanceLevel
lasso_provider_compatibility_level(LassoProvider *provider)
{
	return provider->private_data->conformance;
}

gboolean
lasso_provider_load_metadata(LassoProvider *provider, const gchar *metadata)
{
	xmlDoc *doc;
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *node;
	const char *xpath_idp = "/md:EntityDescriptor/md:IDPDescriptor";
	const char *xpath_sp = "/md:EntityDescriptor/md:SPDescriptor";
	const char *xpath_organization = "/md:EntityDescriptor/md:Organization";

	doc = xmlParseFile(metadata);
	if (doc == NULL)
		return FALSE;

	provider->metadata_filename = g_strdup(metadata);
	provider->private_data->conformance = LIBERTY_1_2;

	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, "md", LASSO_METADATA_HREF);
	xpathObj = xmlXPathEvalExpression("/md:EntityDescriptor", xpathCtx);
	/* if empty: not a ID-FF 1.2 metadata file -> bails out */
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathRegisterNs(xpathCtx, "md11",
				"http://projectliberty.org/schemas/core/2002/12");
		xpathObj = xmlXPathEvalExpression(
				"/md11:SPDescriptor|/md11:IDPDescriptor", xpathCtx);
		if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
			xmlXPathFreeObject(xpathObj);
			xmlFreeDoc(doc);
			xmlXPathFreeContext(xpathCtx);
			return FALSE;
		}
		provider->private_data->conformance = LIBERTY_1_1;
		xpath_idp = "/md11:IDPDescriptor";
		xpath_sp = "/md11:SPDescriptor";
	}
	node = xpathObj->nodesetval->nodeTab[0];
	provider->ProviderID = xmlGetProp(node, "providerID");

	xpathObj = xmlXPathEvalExpression(xpath_idp, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		load_descriptor(xpathObj->nodesetval->nodeTab[0],
				provider->private_data->IDPDescriptor, provider);
		if (provider->private_data->conformance < LIBERTY_1_2) {
			/* lookup ProviderID */
			node = xpathObj->nodesetval->nodeTab[0]->children;
			while (node) {
				if (strcmp(node->name, "ProviderID") == 0) {
					provider->ProviderID = xmlNodeGetContent(node);
					break;
				}
				node = node->next;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression(xpath_sp, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		load_descriptor(xpathObj->nodesetval->nodeTab[0],
				provider->private_data->SPDescriptor, provider);
		if (provider->private_data->conformance < LIBERTY_1_2) {
			/* lookup ProviderID */
			node = xpathObj->nodesetval->nodeTab[0]->children;
			while (node) {
				if (strcmp(node->name, "ProviderID") == 0) {
					provider->ProviderID = xmlNodeGetContent(node);
					break;
				}
				node = node->next;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression(xpath_organization, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		provider->private_data->organization = xmlCopyNode(
				xpathObj->nodesetval->nodeTab[0], 1);
	}
	xmlXPathFreeObject(xpathObj);

	xmlFreeDoc(doc);
	xmlXPathFreeContext(xpathCtx);

	return TRUE;
}

/**
 * lasso_provider_new:
 * @role: provider role, identity provider or service provider
 * @metadata: path to the provider metadata file
 * @public_key: path to the provider public key file (may be a certificate) or NULL
 * @ca_cert_chain: path to the provider CA certificate chain file or NULL
 *
 * Creates a new #LassoProvider.
 *
 * Return value: a newly created #LassoProvider; or NULL if an error occured
 */
LassoProvider*
lasso_provider_new(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain)
{
	LassoProvider *provider;

	provider = LASSO_PROVIDER(g_object_new(LASSO_TYPE_PROVIDER, NULL));
	provider->role = role;
	if (lasso_provider_load_metadata(provider, metadata) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to load metadata from %s.", metadata);
		lasso_node_destroy(LASSO_NODE(provider));
		return NULL;
	}

	provider->public_key = g_strdup(public_key);
	provider->ca_cert_chain = g_strdup(ca_cert_chain);

	lasso_provider_load_public_key(provider);

	return provider;
}

void
lasso_provider_load_public_key(LassoProvider *provider)
{
	LassoPemFileType file_type;
	xmlSecKey *pub_key = NULL;

	if (provider->public_key == NULL)
		return;

	file_type = lasso_get_pem_file_type(provider->public_key);
	switch (file_type) {
		case LASSO_PEM_FILE_TYPE_UNKNOWN:
			break; /* with a warning ? */
		case LASSO_PEM_FILE_TYPE_CERT:
			pub_key = lasso_get_public_key_from_pem_cert_file(
					provider->public_key);
			break;
		case LASSO_PEM_FILE_TYPE_PUB_KEY:
			pub_key = xmlSecCryptoAppKeyLoad(provider->public_key,
					xmlSecKeyDataFormatPem, NULL, NULL, NULL);
			break;
		case LASSO_PEM_FILE_TYPE_PRIVATE_KEY:
			break; /* with a warning ? */
	}
	provider->private_data->public_key = pub_key;
}


/**
 * lasso_provider_new_from_dump:
 * @dump: XML provider dump
 *
 * Restores the @dump to a new #LassoProvider.
 *
 * Return value: a newly created #LassoProvider; or NULL if an error occured.
 **/
LassoProvider*
lasso_provider_new_from_dump(const gchar *dump)
{
	LassoProvider *provider;
	xmlDoc *doc;

	provider = g_object_new(LASSO_TYPE_PROVIDER, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(provider), xmlDocGetRootElement(doc)); 

	lasso_provider_load_public_key(provider);

	return provider;
}

int lasso_provider_verify_signature(LassoProvider *provider,
		const char *message, const char *id_attr_name, LassoMessageFormat format)
{
	/* this duplicates some code from lasso_node_init_from_message;
	 * reflection about code reuse is under way...
	 */
	char *msg;
	xmlDoc *doc;
	xmlNode *xmlnode = NULL, *sign, *x509data;
	xmlSecKeysMngr *keys_mngr = NULL;
	xmlSecDSigCtx *dsigCtx;
	int rc;

	msg = (char*)message;

	if (message == NULL)
		return -2;

	if (format == LASSO_MESSAGE_FORMAT_ERROR)
		return -2;
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN)
		return -2;

	if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		return lasso_query_verify_signature(message, provider->private_data->public_key);
	}

	if (format == LASSO_MESSAGE_FORMAT_BASE64) {
		msg = g_malloc(strlen(message));
		rc = xmlSecBase64Decode(message, msg, strlen(message));
		if (rc < 0) {
			g_free(msg);
			return -3;
		}
	}

	doc = xmlParseMemory(msg, strlen(msg));
	if (format == LASSO_MESSAGE_FORMAT_BASE64) {
		g_free(msg);
		msg = NULL;
	}

	if (format == LASSO_MESSAGE_FORMAT_SOAP) {
		xmlXPathContext *xpathCtx = NULL;
		xmlXPathObject *xpathObj;

		xpathCtx = xmlXPathNewContext(doc);
		xmlXPathRegisterNs(xpathCtx, "s", LASSO_SOAP_ENV_HREF);
		xpathObj = xmlXPathEvalExpression("//s:Body/*", xpathCtx);
		if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr ) {
			xmlnode = xpathObj->nodesetval->nodeTab[0];
		}
		xmlXPathFreeObject(xpathObj);
		xmlXPathFreeContext(xpathCtx);
		if (xmlnode == NULL) {
			xmlFreeDoc(doc);
			return -4;
		}
	} else {
		xmlnode = xmlDocGetRootElement(doc);
	}

	if (id_attr_name) {
		char *id_value = xmlGetProp(xmlnode, id_attr_name);
		xmlAttr *id_attr = xmlHasProp(xmlnode, id_attr_name);
		if (id_value) {
			xmlAddID(NULL, doc, id_value, id_attr);
			xmlFree(id_value);
		}
	}

	sign = NULL;
	for (sign = xmlnode->children; sign; sign = sign->next) {
		if (strcmp(sign->name, "Signature") == 0)
			break;
	}

	if (sign == NULL) {
		xmlFreeDoc(doc);
		return LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
	}

	x509data = xmlSecFindNode(xmlnode, xmlSecNodeX509Data, xmlSecDSigNs);
	if (x509data != NULL && provider->ca_cert_chain != NULL) {
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
				provider->ca_cert_chain);
		if (keys_mngr == NULL) {
			xmlFreeDoc(doc);
			return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
		}
	}

	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);
	if (keys_mngr == NULL) {
		dsigCtx->signKey = provider->private_data->public_key;
		if (dsigCtx->signKey == NULL) {
			/* XXX: should this be detected on lasso_provider_new ? */
			xmlSecDSigCtxDestroy(dsigCtx);
			xmlFreeDoc(doc);
			return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
		}
	}

	if (xmlSecDSigCtxVerify(dsigCtx, sign) < 0) {
		xmlSecDSigCtxDestroy(dsigCtx);
		if (keys_mngr)
			xmlSecKeysMngrDestroy(keys_mngr);
		xmlFreeDoc(doc);
		return LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
	}
	if (keys_mngr)
		xmlSecKeysMngrDestroy(keys_mngr);
	if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
		xmlSecDSigCtxDestroy(dsigCtx);
		xmlFreeDoc(doc);
		return LASSO_DS_ERROR_INVALID_SIGNATURE;
	}

	xmlFreeDoc(doc);
	return 0;
}
