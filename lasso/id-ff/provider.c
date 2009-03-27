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
 * SECTION:provider
 * @short_description: Service or identity provider
 *
 * It holds all the data about a provider.
 **/

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/templates.h>

#include <lasso/id-ff/provider.h>
#include <lasso/id-ff/providerprivate.h>

#include <lasso/saml-2.0/providerprivate.h>
#include <unistd.h>
#include "../utils.h"
#include "../debug.h"

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
static gboolean lasso_provider_load_metadata_from_doc(LassoProvider *provider, xmlDoc *doc);

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

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
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

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
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

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
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
LassoHttpMethod
lasso_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type)
{
	char *protocol_profile_prefix;
	GList *local_supported_profiles;
	GList *remote_supported_profiles;
	GList *t1, *t2 = NULL;
	gboolean found;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), LASSO_HTTP_METHOD_NONE);
	if (provider->private_data->conformance == LASSO_PROTOCOL_SAML_2_0) {
		return lasso_saml20_provider_get_first_http_method(
				provider, remote_provider, protocol_type);
	}

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

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE); /* Be conservative */
	if (provider->private_data->conformance == LASSO_PROTOCOL_SAML_2_0) {
		return lasso_saml20_provider_accept_http_method(
				provider, remote_provider, protocol_type,
				http_method, initiate_profile);
	}

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
				protocol_type, protocol_profile) == FALSE) {
		g_free(protocol_profile);
		return FALSE;
	}

	if (lasso_provider_has_protocol_profile(remote_provider,
				protocol_type, protocol_profile) == FALSE) {
		g_free(protocol_profile);
		return FALSE;
	}

	g_free(protocol_profile);

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

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE); /* Be conservative */
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

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	succinct_id = lasso_sha1(provider->ProviderID);
	base64_succinct_id = (char*)xmlSecBase64Encode((xmlChar*)succinct_id, 20, 0);
	xmlFree(succinct_id);
	return base64_succinct_id;
}


/**
 * lasso_provider_get_organization
 * @provider: a #LassoProvider
 *
 * Returns the provider metadata &lt;Organization&gt; XML node.
 *
 * Return value: the &lt;Organization/&gt; node (libxml2 xmlNode*); or NULL if it is
 *      not found.  This xmlnode must be freed by the caller.
 **/
xmlNode*
lasso_provider_get_organization(LassoProvider *provider)
{
	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	if (provider->private_data->organization) {
		return xmlCopyNode(provider->private_data->organization, 1);
	} else {
		return NULL;
	}
}


/*****************************************************************************/
/* private methods	                                                     */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "PublicKeyFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProvider, public_key), NULL, NULL, NULL},
	{ "CaCertChainFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProvider, ca_cert_chain), NULL, NULL, NULL},
	{ "MetadataFilePath", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoProvider, metadata_filename), NULL, NULL, NULL},
	{ "ProviderID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoProvider, ProviderID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

xmlSecKey*
lasso_provider_get_public_key(LassoProvider *provider)
{
	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	return provider->private_data->public_key;
}

static void
load_descriptor(xmlNode *xmlnode, GHashTable *descriptor, LassoProvider *provider)
{
	xmlNode *t;
	GList *elements;
	char *name;
	xmlChar *value;
	xmlChar *use;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp((char*)t->name, "KeyDescriptor") == 0) {
			use = xmlGetProp(t, (xmlChar*)"use");
			if (use && strcmp((char*)use, "signing") == 0) {
				provider->private_data->signing_key_descriptor = xmlCopyNode(t, 1);
			}
			if (use && strcmp((char*)use, "encryption") == 0) {
				provider->private_data->encryption_key_descriptor =
					xmlCopyNode(t, 1);
			}
			if (use) {
				xmlFree(use);
			}
			t = t->next;
			continue;
		}
		if (strcmp((char*)t->name, "AssertionConsumerServiceURL") == 0) {
			char *isDefault = (char*)xmlGetProp(t, (xmlChar*)"isDefault");
			char *id = (char*)xmlGetProp(t, (xmlChar*)"id");
			name = g_strdup_printf("%s %s", t->name, id);
			if (isDefault) {
				if (strcmp(isDefault, "true") == 0 || strcmp(isDefault, "1") == 0)
					provider->private_data->default_assertion_consumer =
						g_strdup(id);
				xmlFree(isDefault);
			}
			xmlFree(id);
		} else {
			name = g_strdup((char*)t->name);
		}
		elements = g_hash_table_lookup(descriptor, name);
		value = xmlNodeGetContent(t);
		elements = g_list_append(elements, g_strdup((char*)value));
		// Do not mix g_free strings with xmlFree strings
		xmlFree(value);
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
	char *encryption_mode[] = { "None", "NameId", "Assertion", "Both" };

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);

	/* Save provider role */
	xmlSetProp(xmlnode, (xmlChar*)"ProviderDumpVersion", (xmlChar*)"2");
	if (provider->role) {
		xmlSetProp(xmlnode, (xmlChar*)"ProviderRole", (xmlChar*)roles[provider->role]);
	}

	/* Save encryption mode */
	xmlSetProp(xmlnode, (xmlChar*)"EncryptionMode",
		(xmlChar*)encryption_mode[provider->private_data->encryption_mode]);

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoProvider *provider = LASSO_PROVIDER(node);
	xmlChar *s;

	parent_class->init_from_xml(node, xmlnode);

	if (xmlnode == NULL) {
		return LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;
	}

	/* Load provider role */
	s = xmlGetProp(xmlnode, (xmlChar*)"ProviderRole");
	if (s != NULL && strcmp((char*)s, "SP") == 0) {
		provider->role = LASSO_PROVIDER_ROLE_SP;
	} else if (s != NULL && strcmp((char*)s, "IdP") == 0) {
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	}
	if (s != NULL) {
		xmlFree(s);
	}

	/* Load encryption mode */
	s = xmlGetProp(xmlnode, (xmlChar*)"EncryptionMode");
	if (s != NULL && strcmp((char*)s, "NameId") == 0) {
		provider->private_data->encryption_mode = LASSO_ENCRYPTION_MODE_NAMEID;
	} else if (s != NULL && strcmp((char*)s, "Assertion") == 0) {
		provider->private_data->encryption_mode = LASSO_ENCRYPTION_MODE_ASSERTION;
	} else if (s != NULL && strcmp((char*)s, "Both") == 0) {
		provider->private_data->encryption_mode =
			LASSO_ENCRYPTION_MODE_NAMEID | LASSO_ENCRYPTION_MODE_ASSERTION;
	}
	if (s != NULL) {
		xmlFree(s);
	}

	/* Load metadata */
	if (provider->metadata_filename) {
		if (! lasso_provider_load_metadata(provider, provider->metadata_filename)) {
			lasso_provider_load_metadata_from_buffer(provider, provider->metadata_filename);
		}
	}

	/* Load signing and encryption public keys */
	lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_SIGNING);
	lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_ENCRYPTION);

	return 0;
}

/*****************************************************************************/
/* overridden parent class methods	                                     */
/*****************************************************************************/

static void
free_string(char *string)
{
	g_free(string);
}

static void
free_list_strings(G_GNUC_UNUSED gchar *key, GList *list, G_GNUC_UNUSED gpointer data)
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

	if (provider->private_data->signing_key_descriptor) {
		xmlFreeNode(provider->private_data->signing_key_descriptor);
		provider->private_data->signing_key_descriptor = NULL;
	}

	if (provider->private_data->encryption_key_descriptor) {
		xmlFreeNode(provider->private_data->encryption_key_descriptor);
		provider->private_data->encryption_key_descriptor = NULL;
	}

	if (provider->private_data->encryption_public_key_str) {
		g_free(provider->private_data->encryption_public_key_str);
		provider->private_data->encryption_public_key_str = NULL;
	}

	if (provider->private_data->encryption_public_key) {
		xmlSecKeyDestroy(provider->private_data->encryption_public_key);
		provider->private_data->encryption_public_key = NULL;
	}

	g_free(provider->private_data->affiliation_id);
	provider->private_data->affiliation_id = NULL;
	g_free(provider->private_data->affiliation_owner_id);
	provider->private_data->affiliation_owner_id = NULL;

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(provider));
}

static void
finalize(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

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
	provider->private_data->affiliation_id = NULL;
	provider->private_data->affiliation_owner_id = NULL;
	provider->private_data->organization = NULL;
	provider->private_data->public_key = NULL;
	provider->private_data->signing_key_descriptor = NULL;
	provider->private_data->encryption_key_descriptor = NULL;
	provider->private_data->encryption_public_key_str = NULL;
	provider->private_data->encryption_public_key = NULL;
	provider->private_data->encryption_mode = LASSO_ENCRYPTION_MODE_NONE;
	provider->private_data->encryption_sym_key_type = LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_128;

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
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoProvider", &this_info, 0);
	}
	return this_type;
}

LassoProtocolConformance
lasso_provider_get_protocol_conformance(LassoProvider *provider)
{
	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), LASSO_PROTOCOL_NONE);
	return provider->private_data->conformance;
}

/**
 * lasso_provider_load_metadata_from_buffer:
 * @provider: a #LassProvider object
 * @metadata: a char* string containing a metadata XML file.
 *
 * Load metadata into this provider object using the given string buffer.
 *
 * Return value: TRUE if successfull, FALSE otherwise.
 **/
gboolean
lasso_provider_load_metadata_from_buffer(LassoProvider *provider, const gchar *metadata)
{
	xmlDoc *doc;
	gboolean rc = TRUE;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	doc = xmlParseDoc((xmlChar*)metadata);
	if (doc == NULL) {
		char *extract;
		extract = lasso_safe_prefix_string(metadata, 80);
		message(G_LOG_LEVEL_CRITICAL, "Cannot parse metadatas: '%s'", extract);
		lasso_release(extract);
		return FALSE;
	}
	goto_exit_if_fail (lasso_provider_load_metadata_from_doc(provider, doc), FALSE);
	lasso_assign_string(provider->metadata_filename, metadata);
exit:
	lasso_release_doc(doc);
	return rc;

}

/**
 * lasso_provider_load_metadata:
 * @provider: a #LassProvider object
 * @path: the path to a SAML 2.0 of ID-FF 1.2 metadata file.
 *
 * Load metadata into this provider object by reading them from the given file.
 *
 * Return value: TRUE if successfull, FALSE otherwise.
 **/
gboolean
lasso_provider_load_metadata(LassoProvider *provider, const gchar *path)
{
	xmlDoc *doc;
	gboolean rc = TRUE;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	if (access(path, R_OK) != 0) {
		return FALSE;
	}
	doc = xmlParseFile(path);
	goto_exit_if_fail(doc != NULL, FALSE);
	goto_exit_if_fail(lasso_provider_load_metadata_from_doc(provider, doc), FALSE);
	/** Conserve metadata path for future dump/reload */
	lasso_assign_string(provider->metadata_filename, path);
exit:
	lasso_release_doc(doc);
	return rc;
}

static gboolean
lasso_provider_load_metadata_from_doc(LassoProvider *provider, xmlDoc *doc)
{
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *node;
	const char *xpath_idp = "/md:EntityDescriptor/md:IDPDescriptor";
	const char *xpath_sp = "/md:EntityDescriptor/md:SPDescriptor";
	const char *xpath_organization = "/md:EntityDescriptor/md:Organization";

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	if (doc == NULL) {
		return FALSE;
	}

	node = xmlDocGetRootElement(doc);
	if (node == NULL || node->ns == NULL) {
		message (G_LOG_LEVEL_CRITICAL, "lasso_provider_load_metadata_from_doc: no root element");
		return FALSE;
	}


	if (strcmp((char*)node->ns->href, LASSO_SAML2_METADATA_HREF) == 0) {
		gboolean result;
		provider->private_data->conformance = LASSO_PROTOCOL_SAML_2_0;
		result = lasso_saml20_provider_load_metadata(provider, node);
		return result;
	}

	provider->private_data->conformance = LASSO_PROTOCOL_LIBERTY_1_2;

	xpathCtx = xmlXPathNewContext(doc);
	xmlXPathRegisterNs(xpathCtx, (xmlChar*)"md", (xmlChar*)LASSO_METADATA_HREF);
	xpathObj = xmlXPathEvalExpression((xmlChar*)"/md:EntityDescriptor", xpathCtx);
	/* if empty: not a ID-FF 1.2 metadata file -> bails out */
	if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
		xmlXPathFreeObject(xpathObj);
		xmlXPathRegisterNs(xpathCtx, (xmlChar*)"md11",
				(xmlChar*)"http://projectliberty.org/schemas/core/2002/12");
		xpathObj = xmlXPathEvalExpression(
				(xmlChar*)"/md11:SPDescriptor|/md11:IDPDescriptor", xpathCtx);
		if (xpathObj->nodesetval == NULL || xpathObj->nodesetval->nodeNr == 0) {
			message (G_LOG_LEVEL_CRITICAL, "lasso_saml20_provider_load_metadata_from_doc: no md12:EntityDescriptor or md11:SPDesriptor or md11:IDPDescriptor");
			xmlXPathFreeObject(xpathObj);
			xmlXPathFreeContext(xpathCtx);
			return FALSE;
		}
		provider->private_data->conformance = LASSO_PROTOCOL_LIBERTY_1_1;
		xpath_idp = "/md11:IDPDescriptor";
		xpath_sp = "/md11:SPDescriptor";
	}
	node = xpathObj->nodesetval->nodeTab[0];
	provider->ProviderID = (char*)xmlGetProp(node, (xmlChar*)"providerID");
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)xpath_idp, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		load_descriptor(xpathObj->nodesetval->nodeTab[0],
				provider->private_data->IDPDescriptor, provider);
		if (provider->private_data->conformance < LASSO_PROTOCOL_LIBERTY_1_2) {
			/* lookup ProviderID */
			node = xpathObj->nodesetval->nodeTab[0]->children;
			while (node) {
				if (strcmp((char*)node->name, "ProviderID") == 0) {
					provider->ProviderID = (char*)xmlNodeGetContent(node);
					break;
				}
				node = node->next;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)xpath_sp, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		load_descriptor(xpathObj->nodesetval->nodeTab[0],
				provider->private_data->SPDescriptor, provider);
		if (provider->private_data->conformance < LASSO_PROTOCOL_LIBERTY_1_2) {
			/* lookup ProviderID */
			node = xpathObj->nodesetval->nodeTab[0]->children;
			while (node) {
				if (strcmp((char*)node->name, "ProviderID") == 0) {
					provider->ProviderID = (char*)xmlNodeGetContent(node);
					break;
				}
				node = node->next;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)xpath_organization, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		provider->private_data->organization = xmlCopyNode(
				xpathObj->nodesetval->nodeTab[0], 1);
	}
	xmlXPathFreeObject(xpathObj);

	xmlXPathFreeContext(xpathCtx);

	return TRUE;
}

/**
 * lasso_provider_new_helper:
 *
 * Helper function for the two other constructors, lasso_provider_new and lasso_provider_new_from_buffer.
 * Help to factorize common code.
 */
static LassoProvider*
lasso_provider_new_helper(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain, gboolean (*loader)(LassoProvider *provider, const gchar *metadata))
{
	LassoProvider *provider;

	provider = LASSO_PROVIDER(g_object_new(LASSO_TYPE_PROVIDER, NULL));
	provider->role = role;
	if (loader(provider, metadata) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to load metadata from %s.", metadata);
		lasso_node_destroy(LASSO_NODE(provider));
		return NULL;
	}

	provider->public_key = g_strdup(public_key);
	provider->ca_cert_chain = g_strdup(ca_cert_chain);

	if (lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_SIGNING) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to load signing public key for %s.",
				provider->ProviderID);
		lasso_node_destroy(LASSO_NODE(provider));
		return NULL;
	}

	lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_ENCRYPTION);

	provider->private_data->encryption_mode = LASSO_ENCRYPTION_MODE_NONE;

	return provider;
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
	return lasso_provider_new_helper(role, metadata, public_key, ca_cert_chain,
			lasso_provider_load_metadata);
}

/**
 * lasso_provider_new_from_buffer:
 * @role: provider role, identity provider or service provider
 * @metadata: string buffer containing a metadata file
 * @public_key: path to the provider public key file (may be a certificate) or NULL
 * @ca_cert_chain: path to the provider CA certificate chain file or NULL
 *
 * Creates a new #LassoProvider.
 *
 * Return value: a newly created #LassoProvider; or NULL if an error occured
 */
LassoProvider*
lasso_provider_new_from_buffer(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain)
{
	return lasso_provider_new_helper(role, metadata, public_key, ca_cert_chain,
			lasso_provider_load_metadata_from_buffer);
}

gboolean
lasso_provider_load_public_key(LassoProvider *provider, LassoPublicKeyType public_key_type)
{
	LassoPemFileType file_type;
	gchar *public_key = NULL;
	xmlNode	*key_descriptor = NULL;
	xmlSecKey *pub_key = NULL;
	xmlSecKeyDataFormat key_formats[] = {
		xmlSecKeyDataFormatDer,
		xmlSecKeyDataFormatCertDer,
		xmlSecKeyDataFormatPkcs8Der,
		xmlSecKeyDataFormatCertPem,
		xmlSecKeyDataFormatPkcs8Pem,
		xmlSecKeyDataFormatPem,
		xmlSecKeyDataFormatBinary,
		0
	};
	int i;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	if (public_key_type == LASSO_PUBLIC_KEY_SIGNING) {
		public_key = provider->public_key;
		key_descriptor = provider->private_data->signing_key_descriptor;
	} else {
		key_descriptor = provider->private_data->encryption_key_descriptor;
	}

	if (public_key == NULL && key_descriptor == NULL) {
		return FALSE;
	}

	if (public_key == NULL) {
		xmlNode *t = key_descriptor->children;
		xmlChar *b64_value;
		xmlSecByte *value;
		int length;
		int rc = 0;

		/* could use XPath but going down manually will do */
		while (t) {
			if (t->type == XML_ELEMENT_NODE) {
				if (strcmp((char*)t->name, "KeyInfo") == 0 ||
						strcmp((char*)t->name, "X509Data") == 0) {
					t = t->children;
					continue;
				}
				if (strcmp((char*)t->name, "X509Certificate") == 0)
					break;
				if (strcmp((char*)t->name, "KeyValue") == 0)
					break;
			}
			t = t->next;
		}
		if (t == NULL) {
			return FALSE;
		}

		b64_value = xmlNodeGetContent(t);
		if (public_key_type == LASSO_PUBLIC_KEY_ENCRYPTION) {
			provider->private_data->encryption_public_key_str =
				g_strdup((char*)b64_value);
		}
		length = strlen((char*)b64_value);
		value = g_malloc(length);
		xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
		rc = xmlSecBase64Decode(b64_value, value, length);
		if (rc < 0) {
			/* bad base-64 */
			g_free(value);
			value = (xmlSecByte*)g_strdup((char*)b64_value);
			rc = strlen((char*)value);
		}

		for (i=0; key_formats[i] && pub_key == NULL; i++) {
			pub_key = xmlSecCryptoAppKeyLoadMemory(value, rc,
					key_formats[i], NULL, NULL, NULL);
		}
		xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
		xmlFree(b64_value);
		g_free(value);

		if (public_key_type == LASSO_PUBLIC_KEY_SIGNING) {
			provider->private_data->public_key = pub_key;
		} else {
			provider->private_data->encryption_public_key = pub_key;
		}

		if (pub_key) {
			return TRUE;
		}
	}

	if (public_key_type == LASSO_PUBLIC_KEY_ENCRYPTION) {
		/* encryption public key can never be set by filename */
		return FALSE;
	}

	file_type = lasso_get_pem_file_type(public_key);
	switch (file_type) {
		case LASSO_PEM_FILE_TYPE_UNKNOWN:
			break; /* with a warning ? */
		case LASSO_PEM_FILE_TYPE_CERT:
			pub_key = lasso_get_public_key_from_pem_cert_file(public_key);
			break;
		case LASSO_PEM_FILE_TYPE_PUB_KEY:
			pub_key = xmlSecCryptoAppKeyLoad(public_key,
					xmlSecKeyDataFormatPem, NULL, NULL, NULL);
			break;
		case LASSO_PEM_FILE_TYPE_PRIVATE_KEY:
			break; /* with a warning ? */
	}

	provider->private_data->public_key = pub_key;

	return (pub_key != NULL);
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

	if (dump == NULL)
		return NULL;

	provider = g_object_new(LASSO_TYPE_PROVIDER, NULL);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(provider), xmlDocGetRootElement(doc));
	lasso_release_doc(doc);

	return provider;
}

int
lasso_provider_verify_saml_signature(LassoProvider *provider,
		xmlNode *signed_node, xmlDoc *doc)
{
	const char *id_attribute_name = NULL;
	const xmlChar *node_ns = NULL;
	xmlSecKey *public_key;
	xmlSecKeysMngr *keys_manager;
	int rc = 0;

	lasso_bad_param(PROVIDER, provider);
	lasso_null_param(signed_node);
	g_return_val_if_fail((signed_node->doc && doc) || ! signed_node->doc, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* ID-FF 1.2 Signatures case */
	if (xmlSecCheckNodeName(signed_node, (xmlChar*)"Request", (xmlChar*)LASSO_SAML_PROTOCOL_HREF)) {
		id_attribute_name = "RequestID";
	}
	if (xmlSecCheckNodeName(signed_node, (xmlChar*)"Response", (xmlChar*)LASSO_SAML_PROTOCOL_HREF)) {
		id_attribute_name = "ResponseID";
	}
	if (xmlSecCheckNodeName(signed_node, (xmlChar*)"Assertion", (xmlChar*)LASSO_SAML_ASSERTION_HREF)) {
		id_attribute_name = "AssertionID";
	}
	/* SAML 2.0 signature case */
	node_ns = xmlSecGetNodeNsHref(signed_node);
	if ((strcmp((char*)node_ns, LASSO_SAML2_PROTOCOL_HREF) == 0) ||
			(strcmp((char*)node_ns, LASSO_SAML2_ASSERTION_HREF) == 0)) {
		id_attribute_name = "ID";
	}
	goto_exit_if_fail(id_attribute_name, LASSO_PARAM_ERROR_INVALID_VALUE);
	/* Get provider credentials */
	public_key = lasso_provider_get_public_key(provider);
	keys_manager = lasso_load_certs_from_pem_certs_chain_file(provider->ca_cert_chain);
	goto_exit_if_fail_with_warning(public_key || keys_manager,
			LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
	rc = lasso_verify_signature(signed_node, doc, id_attribute_name, keys_manager, public_key,
			NO_OPTION, NULL);
exit:
	lasso_release_key_manager(keys_manager);
	return rc;
}

int
lasso_provider_verify_signature(LassoProvider *provider,
		const char *message, const char *id_attr_name, LassoMessageFormat format)
{
	/* this duplicates some code from lasso_node_init_from_message;
	 * reflection about code reuse is under way...
	 */
	char *msg = NULL;
	xmlDoc *doc = NULL;
	xmlNode *xmlnode = NULL, *sign = NULL, *x509data = NULL;
	xmlSecKeysMngr *keys_mngr = NULL;
	xmlSecDSigCtx *dsigCtx = NULL;
	int rc = 0;
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj = NULL;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (lasso_flag_verify_signature == FALSE)
		return 0;

	msg = (char*)message;
	if (message == NULL)
		return LASSO_PROFILE_ERROR_INVALID_MSG;

	if (format == LASSO_MESSAGE_FORMAT_ERROR)
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN)
		return LASSO_PROFILE_ERROR_INVALID_MSG;

	if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		return lasso_query_verify_signature(message,
				lasso_provider_get_public_key(provider));
	}

	if (format == LASSO_MESSAGE_FORMAT_BASE64) {
		int len;
		msg = g_malloc(strlen(message));
		len = xmlSecBase64Decode((xmlChar*)message, (xmlChar*)msg, strlen(message));
		if (len < 0) {
			goto_exit_with_rc(LASSO_PROFILE_ERROR_INVALID_MSG);
		}
		doc = xmlParseMemory(msg, strlen(msg));
	} else {
		doc = xmlParseMemory(msg, strlen(msg));
		msg = NULL;
	}

	if (format == LASSO_MESSAGE_FORMAT_SOAP) {
		xpathCtx = xmlXPathNewContext(doc);
		xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
		xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body/*", xpathCtx);
		if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr ) {
			xmlnode = xpathObj->nodesetval->nodeTab[0];
		}
		goto_exit_if_fail (xmlnode != NULL, LASSO_PROFILE_ERROR_INVALID_MSG);
	} else {
		xmlnode = xmlDocGetRootElement(doc);
	}


	sign = NULL;
	for (sign = xmlnode->children; sign; sign = sign->next) {
		if (strcmp((char*)sign->name, "Signature") == 0)
			break;
	}

	/* If no signature was found, look for one in assertion */
	if (sign == NULL) {
		for (sign = xmlnode->children; sign; sign = sign->next) {
			if (strcmp((char*)sign->name, "Assertion") == 0)
				break;
		}
		if (sign != NULL) {
			xmlnode = sign;
			for (sign = xmlnode->children; sign; sign = sign->next) {
				if (strcmp((char*)sign->name, "Signature") == 0)
					break;
			}
		}
	}

	goto_exit_if_fail (sign != NULL, LASSO_DS_ERROR_SIGNATURE_NOT_FOUND);

	if (id_attr_name) {
		xmlChar *id_value = xmlGetProp(xmlnode, (xmlChar*)id_attr_name);
		xmlAttr *id_attr = xmlHasProp(xmlnode, (xmlChar*)id_attr_name);
		if (id_value != NULL) {
			xmlAddID(NULL, doc, id_value, id_attr);
			xmlFree(id_value);
		}
	}

	x509data = xmlSecFindNode(xmlnode, xmlSecNodeX509Data, xmlSecDSigNs);
	if (x509data != NULL && provider->ca_cert_chain != NULL) {
		keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
				provider->ca_cert_chain);
		goto_exit_if_fail (keys_mngr != NULL, LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED);
	}

	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);
	if (keys_mngr == NULL) {
		dsigCtx->signKey = xmlSecKeyDuplicate(lasso_provider_get_public_key(provider));
		goto_exit_if_fail (dsigCtx->signKey != NULL, LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
	}

	goto_exit_if_fail (xmlSecDSigCtxVerify(dsigCtx, sign) >= 0, LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);

	if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
		rc = LASSO_DS_ERROR_INVALID_SIGNATURE;
		goto exit;
	}

exit:
	lasso_release_string(msg);
	lasso_release_key_manager(keys_mngr);
	lasso_release_signature_context(dsigCtx);
	if (xpathCtx)
		xmlXPathFreeContext(xpathCtx);
	if (xpathObj)
		xmlXPathFreeObject(xpathObj);
	lasso_release_doc(doc);
	return rc;
}

/**
 * lasso_provider_set_encryption_mode:
 * @provider: provider to set encryption for
 * @encryption_mode: TRUE to activate, FALSE to desactivate
 *
 * Activate or desactivate encryption
 **/
void
lasso_provider_set_encryption_mode(LassoProvider *provider, LassoEncryptionMode encryption_mode)
{
	g_return_if_fail(LASSO_IS_PROVIDER(provider));
	provider->private_data->encryption_mode = encryption_mode;
}

/**
 * lasso_provider_set_encryption_sym_key_type:
 * @provider: provider to set encryption for
 * @encryption_sym_key_type: enum type for generated symetric key
 *
 * Set the type of the generated encryption symetric key
 **/
void
lasso_provider_set_encryption_sym_key_type(LassoProvider *provider,
		LassoEncryptionSymKeyType encryption_sym_key_type)
{
	g_return_if_fail(LASSO_IS_PROVIDER(provider));
	provider->private_data->encryption_sym_key_type = encryption_sym_key_type;
}
