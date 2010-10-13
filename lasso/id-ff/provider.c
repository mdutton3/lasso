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
 * <para>The #LassoProvider object holds metadata about a provider. Metadata are sorted into descriptors,
 * each descriptor being assigned a role. We refer you to <citetitle>Liberty Metadata Description
 * and Discovery
Specification </citetitle> and <citetitle>Metadata for the OASIS Security Assertion Markup Language
(SAML) V2.0</citetitle>.</para>

<para>Roles are represented by the enumeration #LassoProviderRole, you can access descriptors
content using lasso_provider_get_metadata_list_for_role() and lasso_provider_get_metadata_by_role().
Descriptors resources are flattened inside a simple hashtable. For example to get the URL(s) for the
SAML 2.0 single logout response endpoint using binding HTTP-POST of the SP descriptor of a provider
called x, you would call:</para>

<programlisting>
GList *urls = lasso_provider_get_metadata_list_for_role(x, LASSO_PROVIDER_ROLE_SP, "SingleLogoutService HTTP-POST ResponseLocation");
</programlisting>

<para>A provider usually possess a default role stored in the #LassoProvider.role field, which is
initialized by the lasso_server_add_provider() method when registering a new remote provider to our
current provider. The methods lasso_provider_get_metadata() and lasso_provider_get_metadata_list()
use this default role to access descriptors.</para>

 **/

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/base64.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/templates.h>

#include "provider.h"
#include "providerprivate.h"

#include "../saml-2.0/providerprivate.h"
#include <unistd.h>
#include "../utils.h"
#include "../debug.h"

static char *protocol_uris[LASSO_MD_PROTOCOL_TYPE_LAST] = {
	"http://projectliberty.org/profiles/fedterm",
	"http://projectliberty.org/profiles/nim",
	"http://projectliberty.org/profiles/rni",
	"http://projectliberty.org/profiles/slo",
	NULL /* none for single sign on */
};
static char *protocol_md_nodename[LASSO_MD_PROTOCOL_TYPE_LAST] = {
	"FederationTerminationNotificationProtocolProfile",
	"NameIdentifierMappingProtocolProfile",
	"RegisterNameIdentifierProtocolProfile",
	"SingleLogoutProtocolProfile",
	"SingleSignOnProtocolProfile"
};
static char *protocol_roles[LASSO_PROVIDER_ROLE_LAST] = {
	NULL, "idp", "sp",
	"authn-authority", "pdp", "attribute-authority"
};
char *protocol_methods[LASSO_HTTP_METHOD_LAST] = {
	"", "", "", "",
	"", "-http", "-soap"
};

static gboolean _lasso_provider_load_metadata_from_doc(LassoProvider *provider, xmlDoc *doc);
static int _lasso_provider_get_role_index(LassoProviderRole role);
void _lasso_provider_add_metadata_value_for_role(LassoProvider *provider,
		LassoProviderRole role, const char *name, const char *value);
typedef int LassoProviderRoleIndex;

static int
lasso_provider_try_loading_public_key(LassoProvider *provider, xmlSecKeyPtr *public_key, gboolean mandatory) {
	if (provider->public_key || provider->private_data->signing_key_descriptor) {
		*public_key = lasso_provider_get_public_key(provider);
		if (*public_key == NULL)
			return LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
	} else {
		*public_key = NULL;
	}
	if (*public_key == NULL && mandatory)
		return LASSO_PROVIDER_ERROR_MISSING_PUBLIC_KEY;
	return 0;
}

static int
lasso_provider_try_loading_ca_cert_chain(LassoProvider *provider, xmlSecKeysMngrPtr *keys_mngr)
{
	if (provider->ca_cert_chain != NULL) {
		*keys_mngr = lasso_load_certs_from_pem_certs_chain_file(
				provider->ca_cert_chain);
		if (*keys_mngr == NULL)
			return LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
	} else {
		*keys_mngr = NULL;
	}
	return 0;
}

/*****************************************************************************/
/* public methods */
/*****************************************************************************/

/**
 * lasso_provider_get_assertion_consumer_service_url:
 * @provider: a #LassoProvider
 * @service_id:(allow-none): the AssertionConsumerServiceID, NULL for default
 *
 * Extracts the AssertionConsumerServiceURL from the provider metadata
 * descriptor.
 *
 * Return value:(allow-none)(transfer full): the element value, NULL if the element was not found.  This
 *      string must be freed by the caller.
 **/
gchar*
lasso_provider_get_assertion_consumer_service_url(LassoProvider *provider, const char *service_id)
{
	char *name = NULL;
	char *assertion_consumer_service_url = NULL;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);

	if (provider->private_data->conformance == LASSO_PROTOCOL_SAML_2_0) {
		long sid = -1;
		if (service_id != NULL) {
			if (lasso_string_to_xsd_integer(service_id, &sid)) {
				if (sid < 0) {
					sid = -1;
				}
			}
		}
		return lasso_saml20_provider_get_assertion_consumer_service_url(provider, sid);
	}

	if (service_id == NULL)
		service_id = provider->private_data->default_assertion_consumer;
	name = g_strdup_printf("AssertionConsumerServiceURL %s", service_id);
	assertion_consumer_service_url = lasso_provider_get_metadata_one_for_role(provider, LASSO_PROVIDER_ROLE_SP, name);
	lasso_release(name);

	return assertion_consumer_service_url;
}

static LassoProviderRoleIndex
_lasso_provider_get_role_index(LassoProviderRole role) {
	switch (role) {
		case LASSO_PROVIDER_ROLE_IDP:
			return 1;
		case LASSO_PROVIDER_ROLE_SP:
			return 2;
		case LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY:
			return 3;
		case LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY:
			return 4;
		case LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY:
			return 5;
		default:
			return 0;
		}
}

const char *role_to_prefix(LassoProviderRole role) {
	return protocol_roles[_lasso_provider_get_role_index(role)];
}

void
_lasso_provider_add_metadata_value_for_role(LassoProvider *provider, LassoProviderRole role, const char *name, const char *value)
{
	GList *l;
	GHashTable *descriptor;
	char *symbol;
	const char *role_prefix;

	g_return_if_fail(LASSO_IS_PROVIDER(provider) && name && value);
	descriptor = provider->private_data->Descriptors; /* default to SP */
	g_return_if_fail (descriptor);
	l = (GList*)lasso_provider_get_metadata_list_for_role(provider, role, name);
	lasso_list_add_string(l, value);
	if (! l->next) { /* first element added to this key */
		role_prefix = role_to_prefix(role);
		g_return_if_fail(role_prefix);
		symbol = g_strdup_printf("%s %s", role_prefix, name);
		g_hash_table_insert(descriptor, symbol, l);
	}
}

/**
 * lasso_provider_get_metadata_list_for_role:
 * @provider: a #LassoProvider
 * @role: a #LassoProviderRole value
 * @name: the element name
 *
 * Extracts zero to many elements from the @provider descriptor for the given @role.
 *
 * Return value:(transfer none)(element-type string): a #GList with the elements.  This GList is internally
 *      allocated and points to internally allocated strings.  It must
 *      not be freed, modified or stored.
 **/
GList*
lasso_provider_get_metadata_list_for_role(const LassoProvider *provider, LassoProviderRole role, const char *name)
{
	GList *l = NULL;
	GHashTable *descriptor;
	char *symbol;
	const char *role_prefix;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider) && name, NULL);
	g_return_val_if_fail(_lasso_provider_get_role_index(role), NULL);

	descriptor = provider->private_data->Descriptors; /* default to SP */
	if (descriptor == NULL)
		return NULL;

	role_prefix = role_to_prefix(role);
	g_return_val_if_fail(role_prefix, NULL);
	symbol = g_strdup_printf("%s %s", role_prefix, name);
	l = g_hash_table_lookup(descriptor, symbol);
	lasso_release(symbol);

	return l;
}

/**
 * lasso_provider_get_metadata_one_for_role:
 * @provider: a #LassoProvider object
 * @role: a #LassoProviderRole value
 * @name: a metadata information name
 *
 * Return the given information extracted from the metadata of the given #LassoProvider for the
 * given @role descriptor.
 *
 * Retun value: a newly allocated string or NULL. If non-NULL must be freed by the caller.
 */
char*
lasso_provider_get_metadata_one_for_role(LassoProvider *provider, LassoProviderRole role, const char *name)
{
	const GList *l;

	l = lasso_provider_get_metadata_list_for_role(provider, role, name);

	if (l)
		return g_strdup(l->data);
	return NULL;
}

/**
 * lasso_provider_get_metadata_one:
 * @provider: a #LassoProvider
 * @name: the element name
 *
 * Extracts the element @name from the provider metadata descriptor.
 *
 * Return value:(transfer full)(allow-none): the element value, NULL if the element was not found.
 * This string must be freed by the caller.
 **/
gchar*
lasso_provider_get_metadata_one(LassoProvider *provider, const char *name)
{
	return lasso_provider_get_metadata_one_for_role(provider, provider->role, name);
}

/**
 * lasso_provider_get_metadata_list:
 * @provider: a #LassoProvider
 * @name: the element name
 *
 * Extracts zero to many elements from the provider metadata descriptor.
 *
 * Return value:(transfer none)(element-type string): a #GList with the elements.  This GList is internally
 *      allocated and points to internally allocated strings.  It must
 *      not be freed, modified or stored.
 **/
GList*
lasso_provider_get_metadata_list(LassoProvider *provider, const char *name)
{
	return lasso_provider_get_metadata_list_for_role(provider, provider->role, name);
}

/**
 * lasso_provider_get_first_http_method:
 * @provider: (transfer none): a #LassoProvider
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
	const GList *local_supported_profiles;
	const GList *remote_supported_profiles;
	const GList *t1, *t2 = NULL;
	gboolean found;
	const gchar *role_prefix;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), LASSO_HTTP_METHOD_NONE);
	if (provider->private_data->conformance == LASSO_PROTOCOL_SAML_2_0) {
		return lasso_saml20_provider_get_first_http_method(
				provider, remote_provider, protocol_type);
	}

	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP)
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP)
		provider->role = LASSO_PROVIDER_ROLE_SP;

	role_prefix = role_to_prefix(provider->role);
	g_return_val_if_fail(role_prefix, LASSO_HTTP_METHOD_NONE);
	protocol_profile_prefix = g_strdup_printf("%s-%s",
			protocol_uris[protocol_type], role_prefix);

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
	lasso_release(protocol_profile_prefix);

	if (found) {
		if (g_str_has_suffix(t2->data, "http"))
			return LASSO_HTTP_METHOD_REDIRECT;
		if (g_str_has_suffix(t2->data, "soap"))
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
	const gchar *role_prefix;

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

	role_prefix = role_to_prefix(initiating_role);
	g_return_val_if_fail(role_prefix, FALSE);
	protocol_profile = g_strdup_printf("%s-%s%s",
			protocol_uris[protocol_type],
			role_prefix,
			protocol_methods[http_method+1]);

	if (lasso_provider_has_protocol_profile(provider,
				protocol_type, protocol_profile) == FALSE) {
		lasso_release(protocol_profile);
		return FALSE;
	}

	if (lasso_provider_has_protocol_profile(remote_provider,
				protocol_type, protocol_profile) == FALSE) {
		lasso_release(protocol_profile);
		return FALSE;
	}

	lasso_release(protocol_profile);

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
	const GList *supported;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE); /* Be conservative */
	supported = lasso_provider_get_metadata_list(
			provider, protocol_md_nodename[protocol_type]);

	if (g_list_find_custom((GList*)supported, protocol_profile, (GCompareFunc)strcmp) == NULL)
		return FALSE;
	return TRUE;
}

/**
 * lasso_provider_get_base64_succinct_id:
 * @provider: a #LassoProvider
 *
 * Computes and returns the base64-encoded provider succinct ID.
 *
 * Return value:(transfer full)(allow-none): the provider succinct ID.  This string must be freed by the
 *      caller.
 **/
char*
lasso_provider_get_base64_succinct_id(const LassoProvider *provider)
{
	char *succinct_id, *base64_succinct_id, *ret;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	succinct_id = lasso_sha1(provider->ProviderID);
	base64_succinct_id = (char*)xmlSecBase64Encode((xmlChar*)succinct_id, 20, 0);
	xmlFree(succinct_id);
	ret = g_strdup(base64_succinct_id);
	xmlFree(base64_succinct_id);
	return ret;
}

/**
 * lasso_provider_get_organization
 * @provider: a #LassoProvider
 *
 * Returns the provider metadata &lt;Organization&gt; XML node.
 *
 * Return value:(transfer full)(allow-none): the &lt;Organization/&gt; node (libxml2 xmlNode*); or NULL if it is
 *      not found.  This xmlnode must be freed by the caller.
 **/
xmlNode*
lasso_provider_get_organization(const LassoProvider *provider)
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

/**
 * lasso_provider_get_public_key:
 * @provider: a #LassoProvider object
 *
 * Return the public key associated with this provider.
 *
 * Return value: an #xmlSecKey object.
 */
xmlSecKey*
lasso_provider_get_public_key(const LassoProvider *provider)
{
	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	return provider->private_data->public_key;
}

/**
 * lasso_provider_get_encryption_public_key:
 * @provider: a #LassoProvider object.
 *
 * Return the #xmlSecKey public key to use for encrypting content target at @provider.
 *
 * Return value:(transfer none)(allow-none): an #xmlSecKey object, or NULL if no key is known or @provider is not a
 * #LassoProvider.
 */
xmlSecKey*
lasso_provider_get_encryption_public_key(const LassoProvider *provider)
{
	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);

	if (provider->private_data->encryption_public_key) {
		return provider->private_data->encryption_public_key;
	}
	return lasso_provider_get_public_key(provider);
}

static void
_lasso_provider_load_endpoint_type(LassoProvider *provider, xmlNode *endpoint,
		LassoProviderRole role)
{
	char *name = (char*)endpoint->name;
	xmlChar *value = NULL;

	if (strcmp(name, "AssertionConsumerServiceURL") == 0) {
		char *isDefault = (char*)xmlGetProp(endpoint, (xmlChar*)"isDefault");
		char *id = (char*)xmlGetProp(endpoint, (xmlChar*)"id");
		name = g_strdup_printf("%s %s", name, id);
		if (isDefault) {
			if (strcmp(isDefault, "true") == 0 || strcmp(isDefault, "1") == 0)
				lasso_assign_string(provider->private_data->default_assertion_consumer,
					id);
			xmlFree(isDefault);
		}
		xmlFree(id);
	} else {
		name = g_strdup_printf("%s", (char*)name);
	}
	value = xmlNodeGetContent(endpoint);
	_lasso_provider_add_metadata_value_for_role(provider, role, name, (char*)value);
	lasso_release_string(name);
	xmlFree(value);
}

static void
_lasso_provider_load_descriptor(LassoProvider *provider, xmlNode *xmlnode, LassoProviderRole role)
{
	xmlNode *t;

	t = xmlSecGetNextElementNode(xmlnode->children);
	while (t) {
		if (xmlSecCheckNodeName(t,
					BAD_CAST "KeyDescriptor",
					BAD_CAST LASSO_METADATA_HREF)) {
			_lasso_provider_load_key_descriptor(provider, t);
		} else {
			_lasso_provider_load_endpoint_type(provider, t, role);
		}
		t = xmlSecGetNextElementNode(t->next);
	}
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoProvider *provider = LASSO_PROVIDER(node);
	char *roles[LASSO_PROVIDER_ROLE_LAST] = {
		"None",
		"SP",
		"IdP",
		"AuthnAuthority",
		"PDP",
		"AttributeAuthority"
	};
	char *encryption_mode[] = {
		"None",
		"NameId",
		"Assertion",
		"Both"
	};

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

void
_lasso_provider_load_key_descriptor(LassoProvider *provider, xmlNode *key_descriptor)
{
	LassoProviderPrivate *private_data;
	xmlChar *use;

	g_return_if_fail(LASSO_IS_PROVIDER(provider));
	g_return_if_fail(provider->private_data);

	private_data = provider->private_data;
	use = xmlGetProp(key_descriptor, (xmlChar*)"use");
	if (use == NULL || lasso_strisequal((char *)use,"signing")) {
		lasso_assign_xml_node(private_data->signing_key_descriptor, key_descriptor);
	}
	if (use == NULL || strcmp((char*)use, "encryption") == 0) {
		lasso_assign_xml_node(private_data->encryption_key_descriptor, key_descriptor);
	}
	lasso_release_xml_string(use);
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoProvider *provider = LASSO_PROVIDER(node);
	static char * const roles[LASSO_PROVIDER_ROLE_LAST] = {
		"None",
		"SP",
		"IdP",
		"AuthnAuthority",
		"PDP",
		"AttributeAuthority"
	};
	xmlChar *s;
	int i;
	int rc = 0;

	parent_class->init_from_xml(node, xmlnode);

	if (xmlnode == NULL) {
		return LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;
	}

	/* Load provider role */
	s = xmlGetProp(xmlnode, (xmlChar*)"ProviderRole");
	provider->role = LASSO_PROVIDER_ROLE_NONE;
	if (s) {
		i = LASSO_PROVIDER_ROLE_NONE;
		while (i < LASSO_PROVIDER_ROLE_LAST) {
			if (strcmp((char*)s, roles[i]) == 0) {
				provider->role = i;
				break;
			}
			i++;
		}
		lasso_release_xml_string(s);
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
			if (! lasso_provider_load_metadata_from_buffer(provider, provider->metadata_filename)) {
				message(G_LOG_LEVEL_WARNING, "Metadata unrecoverable from dump");
				return 1;
			}
		}
	}

	/* Load signing and encryption public keys */
	if (!lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_SIGNING)) {
		message(G_LOG_LEVEL_WARNING, "Could not load public signing key of %s",
				provider->ProviderID);
		rc = 1;
	}
	if (!lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_ENCRYPTION)) {
		message(G_LOG_LEVEL_WARNING, "Could not load public encryption key of %s",
				provider->ProviderID);
		rc = 1;
	}

	return rc;
}

static void*
_lasso_provider_get_pdata_thing(LassoProvider *provider, ptrdiff_t offset)
{
	LassoProviderPrivate *pdata;

	lasso_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	pdata = provider->private_data;
	if (pdata)
		return G_STRUCT_MEMBER_P(pdata, offset);

	return NULL;
}

/**
 * lasso_provider_get_idp_supported_attributes:
 * @provider: a #LassoProvider object
 *
 * If the provider supports the IDP SSO role, then return the list of Attribute definition that this
 * provider declared supporting.
 *
 * Return value:(transfer none)(element-type LassoNode): a list of #LassoSaml2Attribute or #LassoSamlAttribute
 */
GList*
lasso_provider_get_idp_supported_attributes(LassoProvider *provider)
{
	return _lasso_provider_get_pdata_thing(provider, G_STRUCT_OFFSET(LassoProviderPrivate,
				attributes));
}

/**
 * lasso_provider_get_valid_until:
 * @provider: a #LassoProvider object
 *
 * Return the time after which the metadata for this provider will become invalid. This is an
 * ISO-8601 formatted string.
 *
 * Return value:(transfer none): an internally allocated string, you can copy it but not store it.
 */
char*
lasso_provider_get_valid_until(LassoProvider *provider)
{
	return _lasso_provider_get_pdata_thing(provider,
			G_STRUCT_OFFSET(LassoProviderPrivate, valid_until));
}

/**
 * lasso_provider_get_cache_duration:
 * @provider: a #LassoProvider object
 *
 * Return the time during which the metadata for this provider can be kept.
 *
 * Return value:(transfer none): an internally allocated string, you can copy it but not store it.
 */
char*
lasso_provider_get_cache_duration(LassoProvider *provider)
{
	return _lasso_provider_get_pdata_thing(provider,
			G_STRUCT_OFFSET(LassoProviderPrivate, cache_duration));
}


/*****************************************************************************/
/* overridden parent class methods	                                     */
/*****************************************************************************/

static void
free_list_strings(GList *list)
{
	lasso_release_list_of_strings(list);
}

static void
lasso_endpoint_free(EndpointType *endpoint_type) {
	g_free(endpoint_type->binding);
	g_free(endpoint_type->url);
	g_free(endpoint_type->kind);
	g_free(endpoint_type->return_url);
	g_free(endpoint_type);
}


static void
dispose(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

	if (provider->private_data->dispose_has_run) {
		return;
	}
	provider->private_data->dispose_has_run = TRUE;

	lasso_release_ghashtable(provider->private_data->Descriptors);

	if (provider->private_data->organization) {
		xmlFreeNode(provider->private_data->organization);
		provider->private_data->organization = NULL;
	}

	if (provider->private_data->default_assertion_consumer) {
		lasso_release(provider->private_data->default_assertion_consumer);
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
		lasso_release(provider->private_data->encryption_public_key_str);
		provider->private_data->encryption_public_key_str = NULL;
	}

	if (provider->private_data->encryption_public_key) {
		xmlSecKeyDestroy(provider->private_data->encryption_public_key);
		provider->private_data->encryption_public_key = NULL;
	}

	lasso_release(provider->private_data->affiliation_id);
	provider->private_data->affiliation_id = NULL;
	lasso_release(provider->private_data->affiliation_owner_id);
	provider->private_data->affiliation_owner_id = NULL;
	lasso_release_list_of_full(provider->private_data->endpoints, lasso_endpoint_free);

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(provider));
}

static void
finalize(GObject *object)
{
	LassoProvider *provider = LASSO_PROVIDER(object);

	lasso_release(provider->private_data);
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
	provider->private_data = g_new0(LassoProviderPrivate, 1);
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
	provider->private_data->Descriptors = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, (GFreeFunc)free_list_strings);
	provider->private_data->attributes = NULL;
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

/**
 * lasso_provider_get_protocol_conformance:
 * @provider: a #LassoProvider object
 *
 * Return the protocol conformance of the given provider, it should allow to switch behaviour of SP
 * and IdP code toward a specific protocol. See also #LassoProtocolConformance.
 *
 * Return value: a value in the #LassoProtocolConformance enumeration.
 */
LassoProtocolConformance
lasso_provider_get_protocol_conformance(const LassoProvider *provider)
{
	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), LASSO_PROTOCOL_NONE);
	return provider->private_data->conformance;
}

gboolean
_lasso_provider_load_metadata_from_buffer(LassoProvider *provider, const gchar *metadata, int length)
{
	xmlDoc *doc;
	gboolean rc = TRUE;

	lasso_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	if (length == -1) {
		length = strlen(metadata);
	}
	doc = lasso_xml_parse_memory(metadata, length);
	if (doc == NULL) {
		return FALSE;
	}
	goto_cleanup_if_fail_with_rc (_lasso_provider_load_metadata_from_doc(provider, doc), FALSE);
	lasso_assign_string(provider->metadata_filename, metadata);
cleanup:
	lasso_release_doc(doc);
	return rc;
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
	return _lasso_provider_load_metadata_from_buffer(provider, metadata, -1);
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
	char *file_content;
	size_t file_length;

	if (g_file_get_contents(path, &file_content, &file_length, NULL)) {
		gboolean ret;
		ret = _lasso_provider_load_metadata_from_buffer(provider, file_content, file_length);
		lasso_release(file_content);
		return ret;
	}
	return FALSE;
}

static gboolean
_lasso_provider_load_metadata_from_doc(LassoProvider *provider, xmlDoc *doc)
{
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNode *node;
	const char *xpath_idp = "/md:EntityDescriptor/md:IDPDescriptor";
	const char *xpath_sp = "/md:EntityDescriptor/md:SPDescriptor";
	const char *xpath_organization = "/md:EntityDescriptor/md:Organization";
	xmlChar *providerID = NULL;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	if (doc == NULL) {
		warning("Metadata is not an XML document");
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
	providerID = xmlGetProp(node, (xmlChar*)"providerID");
	lasso_assign_string(provider->ProviderID, (char*)providerID);
	lasso_release_xml_string(providerID);
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)xpath_idp, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		_lasso_provider_load_descriptor(provider, xpathObj->nodesetval->nodeTab[0],
				LASSO_PROVIDER_ROLE_IDP);
		if (provider->private_data->conformance < LASSO_PROTOCOL_LIBERTY_1_2) {
			/* lookup ProviderID */
			node = xpathObj->nodesetval->nodeTab[0]->children;
			while (node) {
				if (strcmp((char*)node->name, "ProviderID") == 0) {
					providerID = xmlNodeGetContent(node);
					lasso_assign_string(provider->ProviderID, (char*)providerID);
					lasso_release_xml_string(providerID);
					break;
				}
				node = node->next;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)xpath_sp, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		_lasso_provider_load_descriptor(provider, xpathObj->nodesetval->nodeTab[0],
				LASSO_PROVIDER_ROLE_SP);
		if (provider->private_data->conformance < LASSO_PROTOCOL_LIBERTY_1_2) {
			/* lookup ProviderID */
			node = xpathObj->nodesetval->nodeTab[0]->children;
			while (node) {
				if (strcmp((char*)node->name, "ProviderID") == 0) {
					providerID = xmlNodeGetContent(node);
					lasso_assign_string(provider->ProviderID, (char*)providerID);
					lasso_release_xml_string(providerID);
					break;
				}
				node = node->next;
			}
		}
	}
	xmlXPathFreeObject(xpathObj);

	xpathObj = xmlXPathEvalExpression((xmlChar*)xpath_organization, xpathCtx);
	if (xpathObj && xpathObj->nodesetval && xpathObj->nodesetval->nodeNr == 1) {
		lasso_assign_xml_node(provider->private_data->organization,
				xpathObj->nodesetval->nodeTab[0]);
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
_lasso_provider_new_helper(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain, gboolean (*loader)(
			LassoProvider *provider, const gchar *metadata))
{
	LassoProvider *provider = NULL, *ret = NULL;

	provider = (LassoProvider*)g_object_new(LASSO_TYPE_PROVIDER, NULL);
	provider->role = role;
	if (loader(provider, metadata) == FALSE) {
		if (loader == lasso_provider_load_metadata) {
			message(G_LOG_LEVEL_WARNING, "Cannot load metadata from %s", metadata);
		}
		goto cleanup;
	}

	lasso_assign_string(provider->public_key, public_key);
	lasso_assign_string(provider->ca_cert_chain, ca_cert_chain);
	if (!lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_SIGNING)) {
		message(G_LOG_LEVEL_WARNING, "Could not load public signing key of %s",
				provider->ProviderID);
		goto cleanup;
	}
	if (!lasso_provider_load_public_key(provider, LASSO_PUBLIC_KEY_ENCRYPTION)) {
		message(G_LOG_LEVEL_WARNING, "Could not load public encryption key of %s",
				provider->ProviderID);
		goto cleanup;
	}

	provider->private_data->encryption_mode = LASSO_ENCRYPTION_MODE_NONE;
	lasso_transfer_gobject(ret, provider);
cleanup:
	lasso_release_gobject(provider);
	return ret;
}
/**
 * lasso_provider_new:
 * @role: provider role, identity provider or service provider
 * @metadata: path to the provider metadata file
 * @public_key:(allow-none): path to the provider public key file (may be a certificate) or NULL
 * @ca_cert_chain:(allow-none): path to the provider CA certificate chain file or NULL
 *
 * Creates a new #LassoProvider.
 *
 * Return value: a newly created #LassoProvider; or NULL if an error occured
 */
LassoProvider*
lasso_provider_new(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain)
{
	return _lasso_provider_new_helper(role, metadata, public_key, ca_cert_chain,
			lasso_provider_load_metadata);
}

/**
 * lasso_provider_new_from_buffer:
 * @role: provider role, identity provider or service provider
 * @metadata: string buffer containing a metadata file
 * @public_key:(allow-none): path to the provider public key file (may be a certificate) or NULL
 * @ca_cert_chain:(allow-none): path to the provider CA certificate chain file or NULL
 *
 * Creates a new #LassoProvider.
 *
 * Return value: a newly created #LassoProvider; or NULL if an error occured
 */
LassoProvider*
lasso_provider_new_from_buffer(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain)
{
	return _lasso_provider_new_helper(role, metadata, public_key, ca_cert_chain,
			lasso_provider_load_metadata_from_buffer);
}

/**
 * lasso_provider_load_public_key:
 * @provider: a #LassoProvider object
 * @public_key_type: the type of public key to load
 *
 * Load the public key from their transport format, a file or a KeyDescriptor #xmlNode.
 *
 * Return value: TRUE if loading was succesfull, FALSE otherwise.
 */
gboolean
lasso_provider_load_public_key(LassoProvider *provider, LassoPublicKeyType public_key_type)
{
	gchar *public_key = NULL;
	xmlNode *key_descriptor = NULL;
	xmlSecKey *pub_key = NULL;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), FALSE);
	if (public_key_type == LASSO_PUBLIC_KEY_SIGNING) {
		public_key = provider->public_key;
		key_descriptor = provider->private_data->signing_key_descriptor;
	} else {
		key_descriptor = provider->private_data->encryption_key_descriptor;
	}

	if (public_key == NULL && key_descriptor == NULL) {
		return TRUE;
	}

	if (public_key == NULL) {
		pub_key = lasso_xmlsec_load_key_info(key_descriptor);
		if (! pub_key) {
			message(G_LOG_LEVEL_WARNING, "Could not read KeyInfo from %s KeyDescriptor", public_key_type == LASSO_PUBLIC_KEY_SIGNING ? "signing" : "encryption");
		}
	} else {
		pub_key = lasso_xmlsec_load_private_key(public_key, NULL);
	}

	if (pub_key) {
		switch (public_key_type) {
			case LASSO_PUBLIC_KEY_SIGNING:
				lasso_assign_new_sec_key(provider->private_data->public_key, pub_key);
				break;
			case LASSO_PUBLIC_KEY_ENCRYPTION:
				lasso_assign_new_sec_key(provider->private_data->encryption_public_key, pub_key);
				break;
			default:
				xmlSecKeyDestroy(pub_key);
		}
	}

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

	provider = (LassoProvider*)lasso_node_new_from_dump(dump);
	if (! LASSO_IS_PROVIDER(provider)) {
		lasso_release_gobject(provider);
	}
	return provider;
}

int
lasso_provider_verify_saml_signature(LassoProvider *provider,
		xmlNode *signed_node, xmlDoc *doc)
{
	const char *id_attribute_name = NULL;
	const xmlChar *node_ns = NULL;
	xmlSecKey *public_key = NULL;
	xmlSecKeysMngr *keys_manager = NULL;
	int rc = 0;

	lasso_bad_param(PROVIDER, provider);
	lasso_null_param(signed_node);
	g_return_val_if_fail((signed_node->doc && doc) || ! signed_node->doc, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* ID-FF 1.2 Signatures case */
	node_ns = xmlSecGetNodeNsHref(signed_node);
	if ((strcmp((char*)node_ns, LASSO_SAML2_PROTOCOL_HREF) == 0) ||
			(strcmp((char*)node_ns, LASSO_SAML2_ASSERTION_HREF) == 0)) {
		id_attribute_name = "ID";
	} else if (xmlSecCheckNodeName(signed_node, (xmlChar*)"Request", (xmlChar*)LASSO_SAML_PROTOCOL_HREF)) {
		id_attribute_name = "RequestID";
	} else if (xmlSecCheckNodeName(signed_node, (xmlChar*)"Response", (xmlChar*)LASSO_SAML_PROTOCOL_HREF)) {
		id_attribute_name = "ResponseID";
	} else if (xmlSecCheckNodeName(signed_node, (xmlChar*)"Assertion", (xmlChar*)LASSO_SAML_ASSERTION_HREF)) {
		id_attribute_name = "AssertionID";
	}
	goto_cleanup_if_fail_with_rc(id_attribute_name, LASSO_PARAM_ERROR_INVALID_VALUE);
	/* Get provider credentials */
	lasso_check_good_rc(lasso_provider_try_loading_ca_cert_chain(provider, &keys_manager));
	lasso_check_good_rc(lasso_provider_try_loading_public_key(provider, &public_key, keys_manager == NULL));
	rc = lasso_verify_signature(signed_node, doc, id_attribute_name, keys_manager, public_key,
			NO_OPTION, NULL);
cleanup:
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
	xmlDoc *doc = NULL;
	xmlNode *xmlnode = NULL, *sign = NULL, *x509data = NULL;
	xmlSecKeysMngr *keys_mngr = NULL;
	xmlSecDSigCtx *dsigCtx = NULL;
	int rc = 0;
	xmlXPathContext *xpathCtx = NULL;
	xmlXPathObject *xpathObj = NULL;
	xmlSecKey *public_key = NULL;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (lasso_flag_verify_signature == FALSE)
		return 0;


	if (message == NULL)
		return LASSO_PROFILE_ERROR_INVALID_MSG;

	if (format == LASSO_MESSAGE_FORMAT_ERROR)
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN)
		return LASSO_PROFILE_ERROR_INVALID_MSG;

	if (format == LASSO_MESSAGE_FORMAT_QUERY) {
		lasso_check_good_rc(lasso_provider_try_loading_public_key(provider, &public_key, TRUE));

		switch (lasso_provider_get_protocol_conformance(provider)) {
			case LASSO_PROTOCOL_LIBERTY_1_0:
			case LASSO_PROTOCOL_LIBERTY_1_1:
			case LASSO_PROTOCOL_LIBERTY_1_2:
				return lasso_query_verify_signature(message, public_key);
			case LASSO_PROTOCOL_SAML_2_0:
				return lasso_saml2_query_verify_signature(message, public_key);
			default:
				return LASSO_PROFILE_ERROR_CANNOT_VERIFY_SIGNATURE;
		}
	}
	lasso_check_good_rc(lasso_provider_try_loading_ca_cert_chain(provider, &keys_mngr));
	/* public key is mandatory if no keys manager is present */
	lasso_check_good_rc(lasso_provider_try_loading_public_key(provider, &public_key, keys_mngr == NULL));

	if (format == LASSO_MESSAGE_FORMAT_BASE64) {
		int len;
		char *msg = g_malloc(strlen(message));
		len = xmlSecBase64Decode((xmlChar*)message, (xmlChar*)msg, strlen(message));
		if (len < 0) {
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_MSG);
		}
		doc = lasso_xml_parse_memory(msg, strlen(msg));
		lasso_release_string(msg);
	} else {
		doc = lasso_xml_parse_memory(message, strlen(message));
	}

	if (format == LASSO_MESSAGE_FORMAT_SOAP) {
		xpathCtx = xmlXPathNewContext(doc);
		xmlXPathRegisterNs(xpathCtx, (xmlChar*)"s", (xmlChar*)LASSO_SOAP_ENV_HREF);
		xpathObj = xmlXPathEvalExpression((xmlChar*)"//s:Body/*", xpathCtx);
		if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr ) {
			xmlnode = xpathObj->nodesetval->nodeTab[0];
		}
		goto_cleanup_if_fail_with_rc (xmlnode != NULL, LASSO_PROFILE_ERROR_INVALID_MSG);
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

	goto_cleanup_if_fail_with_rc (sign != NULL, LASSO_DS_ERROR_SIGNATURE_NOT_FOUND);

	if (id_attr_name) {
		xmlChar *id_value = xmlGetProp(xmlnode, (xmlChar*)id_attr_name);
		xmlAttr *id_attr = xmlHasProp(xmlnode, (xmlChar*)id_attr_name);
		if (id_value != NULL) {
			xmlAddID(NULL, doc, id_value, id_attr);
			xmlFree(id_value);
		}
	}

	x509data = xmlSecFindNode(xmlnode, xmlSecNodeX509Data, xmlSecDSigNs);
	if (x509data == NULL) { /* no need for a keys mngr if there is no X509 data */
		lasso_release_key_manager(keys_mngr);
	}

	dsigCtx = xmlSecDSigCtxCreate(keys_mngr);
	if (public_key) {
		dsigCtx->signKey = xmlSecKeyDuplicate(public_key);
	}

	goto_cleanup_if_fail_with_rc (xmlSecDSigCtxVerify(dsigCtx, sign) >= 0,
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);

	if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
		rc = LASSO_DS_ERROR_INVALID_SIGNATURE;
		goto cleanup;
	}

cleanup:
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
 * lasso_provider_get_encryption_mode:
 * @provider: a #LassoProvider object
 *
 * Return the current encryption mode.
 *
 * Return value: a value in the #LassoEncryptionMode enumeration.
 */
LassoEncryptionMode
lasso_provider_get_encryption_mode(LassoProvider *provider) {
	if (! LASSO_IS_PROVIDER(provider) || ! provider->private_data)
		return LASSO_ENCRYPTION_MODE_NONE;
	return provider->private_data->encryption_mode;
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

/**
 * lasso_provider_get_encryption_sym_key_type:
 * @provider: a #LassoProvider object
 *
 * Return the encryption sym key type for this provider.
 *
 * Return value: a #LassoEncryptionSymKeyType value.
 */
LassoEncryptionSymKeyType
lasso_provider_get_encryption_sym_key_type(const LassoProvider *provider)
{
	if (LASSO_IS_PROVIDER(provider) && provider->private_data)
		return provider->private_data->encryption_sym_key_type;

	return LASSO_ENCRYPTION_SYM_KEY_TYPE_DEFAULT;
}

/**
 * lasso_provider_verify_query_signature:
 * @provider: the #LassoProvider for the the provider issuing the query
 * @message: the URL query string UTF-8 encoded
 *
 * Retrieve the public key of the given provider and verify the signature of the query string.
 *
 * Return value: 0 if succesfull,
 * <itemizedlist>
 * <listitem><para>#LASSO_PROVIDER_ERROR_MISSING_PUBLIC_KEY if no public key is set for this provider,</para></listitem>
 * <listitem><para>#LASSO_DS_ERROR_INVALID_SIGNATURE if signature is invalid,</para></listitem>
 * <listitem><para>#LASSO_DS_ERROR_SIGNATURE_NOT_FOUND if no signature is found,</para></listitem>
 * <listitem><para>#LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED if the key cannot be loaded,</para></listitem>
 * <listitem><para>#LASSO_ERROR_UNIMPLEMENTED if the protocol profile of the provider is invalid or not supported.</para></listitem>
 * </itemizedlist>
 */
int
lasso_provider_verify_query_signature(LassoProvider *provider, const char *message)
{
	xmlSecKey *provider_public_key;
	int rc = 0;

	lasso_bad_param(PROVIDER, provider);
	lasso_check_good_rc(lasso_provider_try_loading_public_key(provider, &provider_public_key, TRUE));
	g_return_val_if_fail(provider_public_key, LASSO_PROVIDER_ERROR_MISSING_PUBLIC_KEY);

	switch (lasso_provider_get_protocol_conformance(provider)) {
		case LASSO_PROTOCOL_LIBERTY_1_0:
		case LASSO_PROTOCOL_LIBERTY_1_1:
		case LASSO_PROTOCOL_LIBERTY_1_2:
			return lasso_query_verify_signature(message, provider_public_key);
		case LASSO_PROTOCOL_SAML_2_0:
			return lasso_saml2_query_verify_signature(message, provider_public_key);
		default:
			return LASSO_ERROR_UNIMPLEMENTED;
	}
cleanup:
	return rc;
}

/**
 * lasso_provider_get_default_name_id_format:
 * @provider: a #LassoProvider object
 *
 * If the provider has a list of supported name id formats in its metadatas, return the first one.
 *
 * Return value:(transfer full)(allow-none): a NameIDFormat URI or NULL, the returned value must be freed by the caller.
 */
gchar*
lasso_provider_get_default_name_id_format(LassoProvider *provider)
{
	return lasso_provider_get_metadata_one(provider, "NameIDFormat");
}

/**
 * lasso_provider_get_sp_name_qualifier:
 * @provider: a #LassoPRovider object
 *
 * Return the entityID to use for qualifying NameIdentifier.
 *
 * Return value:(transfer none)(allow-none): a private string or NULL. Do not keep a reference on this string or
 * free it.
 */
const char*
lasso_provider_get_sp_name_qualifier(LassoProvider *provider)
{
	const char *sp_name_qualifier;

	g_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	/* should not happen ! */
	g_return_val_if_fail(provider->private_data != NULL, NULL);

	if (provider->private_data->affiliation_id) {
		sp_name_qualifier = provider->private_data->affiliation_id;
	} else {
		sp_name_qualifier = provider->ProviderID;
	}

	if (sp_name_qualifier) {
		return sp_name_qualifier;
	} else {
		return NULL;
	}
}

/**
 * lasso_provider_verify_single_node_signature:
 * @provider: a #LassoProvider object
 * @node: a #LassoNode object, still having its originalXmlnode content, and containing an XML
 * signature.
 * @id_attr_name: the name of the ID attribute to lookup.
 *
 * Return wheter the provider signed this node.
 *
 * Return value: 0 if the node is signed by this provider, an error code otherwise.
 */
int
lasso_provider_verify_single_node_signature (LassoProvider *provider, LassoNode *node, const char *id_attr_name)
{
	xmlNode *xmlnode = NULL;
	xmlSecKey *public_key = NULL;
	xmlSecKeysMngr *keys_mngr = NULL;
	int rc = 0;

	xmlnode = lasso_node_get_original_xmlnode (node);
	if (xmlnode == NULL) {
		return LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
	}
	lasso_check_good_rc(lasso_provider_try_loading_ca_cert_chain(provider, &keys_mngr));
	lasso_check_good_rc(lasso_provider_try_loading_public_key(provider, &public_key,
				keys_mngr == NULL));
	rc = lasso_verify_signature(xmlnode, NULL, id_attr_name, keys_mngr, public_key,
			NO_SINGLE_REFERENCE, NULL);
cleanup:
	return rc;
}

struct AddForRoleHelper {
	GList *l;
	LassoProviderRole role;
};


static void
_add_for_role(gpointer key, G_GNUC_UNUSED gpointer data, struct AddForRoleHelper *helper)
{
	char role_prefix[64];
	int l;

	l = sprintf(role_prefix, "%s ", role_to_prefix(helper->role));

	if (key && strncmp(key, role_prefix, l) == 0) {
		lasso_list_add_string(helper->l, ((char*)key) + l);
	}
}

/**
 * lasso_provider_get_metadata_keys_for_role:
 * @provider: a #LassoProvider object
 * @role: a #LassoProviderRole value
 *
 * Returns the list of metadata keys existing for the given provider.
 *
 * Return value:(element-type utf8)(transfer full): a newly allocated list of strings
 */
GList*
lasso_provider_get_metadata_keys_for_role(LassoProvider *provider, LassoProviderRole role)
{
	struct AddForRoleHelper helper = { NULL, role };

	lasso_return_val_if_fail(LASSO_IS_PROVIDER(provider), NULL);
	lasso_return_val_if_fail(provider->private_data != NULL, NULL);
	lasso_return_val_if_fail(role > LASSO_PROVIDER_ROLE_NONE && role < LASSO_PROVIDER_ROLE_LAST, NULL);
	g_return_val_if_fail(role_to_prefix(role) != NULL, NULL);

	g_hash_table_foreach(provider->private_data->Descriptors, (GHFunc)_add_for_role, &helper);

	return helper.l;
}

/**
 * lasso_provider_get_roles:
 * @provider: a #LassoProvider object
 *
 * Return the bitmask of the supported roles.
 *
 * Return value: a #LassoProviderRole enumeration value.
 */
LassoProviderRole
lasso_provider_get_roles(LassoProvider *provider)
{
	lasso_return_val_if_fail(LASSO_IS_PROVIDER(provider) && provider->private_data, LASSO_PROVIDER_ROLE_NONE);

	return provider->private_data->roles;
}

/**
 * lasso_provider_match_conformance:
 * @provider: a #LassoProvider object
 * @another_provider: a #LassoProvider object
 *
 * Return whether the two provider support a same protocol.
 * See also #LassoProtocolConformance.
 *
 * Return value: TRUE or FALSE.
 */
gboolean
lasso_provider_match_conformance(LassoProvider *provider, LassoProvider *another_provider)
{
	lasso_return_val_if_fail(LASSO_IS_PROVIDER(provider)
			&& LASSO_IS_PROVIDER(another_provider),
			FALSE);

	int conformance1 = lasso_provider_get_protocol_conformance(provider);
	int conformance2 = lasso_provider_get_protocol_conformance(another_provider);

	return (conformance1 & conformance2) != 0;
}
