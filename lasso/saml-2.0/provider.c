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

#define _POSIX_SOURCE

#include "../xml/private.h"
#include <xmlsec/base64.h>
#include <xmlsec/xmltree.h>

#include "providerprivate.h"
#include "../id-ff/providerprivate.h"
#include "../utils.h"
#include "./provider.h"
#include "../xml/saml-2.0/saml2_attribute.h"
#include "../xml/saml-2.0/saml2_xsd.h"

const char *profile_names[LASSO_MD_PROTOCOL_TYPE_LAST] = {
	"", /* No fedterm in SAML 2.0 */
	"NameIDMappingService",  /*IDPSSODescriptor*/
	"", /* No rni in SAML 2.0 */
	"SingleLogoutService",   /*SSODescriptor*/
	"SingleSignOnService",  /*IDPSSODescriptor*/
	"ArtifactResolutionService",  /*SSODescriptor*/
	"ManageNameIDService",    /*SSODescriptor*/
	"AssertionIDRequestService", /* IDPSSODescriptor,
                                        AuthnAuhtorityDescriptor,
                                        PDPDescriptor,
                                        AttributeAuthorityDescriptor */
	"AuthnQueryService",  /*AuthnAuthorityDescriptor*/
	"AuthzService",  /*PDPDescriptor*/
	"AttributeService" /*AttributeAuthorityDescriptor*/
};

static void add_assertion_consumer_url_to_list(gchar *key, G_GNUC_UNUSED gpointer value, GList **list);

static const char*
binding_uri_to_identifier(const char *uri)
{
	if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_SOAP) == 0) {
		return "SOAP";
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_REDIRECT) == 0) {
		return "HTTP-Redirect";
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_POST) == 0) {
		return "HTTP-POST";
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_ARTIFACT) == 0) {
		return "HTTP-Artifact";
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_PAOS) == 0) {
		return "PAOS";
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_URI) == 0) {
		return "URI";
	}
	return NULL;
}

static const char*
identifier_to_binding_uri(const char *identifier)
{
	if (strcmp(identifier, "SOAP") == 0) {
		return LASSO_SAML2_METADATA_BINDING_SOAP;
	} else if (strcmp(identifier, "HTTP-Redirect") == 0) {
		return LASSO_SAML2_METADATA_BINDING_REDIRECT;
	} else if (strcmp(identifier, "HTTP-POST") == 0) {
		return LASSO_SAML2_METADATA_BINDING_POST;
	} else if (strcmp(identifier, "HTTP-Artifact") == 0) {
		return LASSO_SAML2_METADATA_BINDING_ARTIFACT;
	} else if (strcmp(identifier, "PAOS") == 0) {
		return LASSO_SAML2_METADATA_BINDING_PAOS;
	} else if (strcmp(identifier, "URI") == 0) {
		return LASSO_SAML2_METADATA_BINDING_URI;
	}
	return NULL;
}

static gboolean
checkSaml2MdNode(xmlNode *t, char *name)
{
	return xmlSecCheckNodeName(t,
			BAD_CAST name,
			BAD_CAST LASSO_SAML2_METADATA_HREF);
}

static xmlChar*
getSaml2MdProp(xmlNode *t, char *name) {
	return xmlGetProp(t, BAD_CAST name);
}

static gboolean
hasSaml2MdProp(xmlNode *t, char *name) {
	return xmlHasProp(t, BAD_CAST name) != NULL;
}

static gboolean
xsdIsTrue(xmlChar *value)
{
	if (value && strcmp((char*)value, "true") == 0)
		return TRUE;
	return FALSE;
}

static gboolean
xsdIsFalse(xmlChar *value)
{
	if (value && strcmp((char*)value, "false") == 0)
		return TRUE;
	return FALSE;
}

static void
load_endpoint_type(xmlNode *xmlnode, LassoProvider *provider, LassoProviderRole role)
{
	xmlChar *binding = xmlGetProp(xmlnode, BAD_CAST "Binding");
	char *name = NULL;
	char *response_name = NULL;
	LassoProviderPrivate *private_data = provider->private_data;
	const char *binding_s = NULL;
	xmlChar *value = NULL;
	xmlChar *response_value = NULL;


	binding_s = binding_uri_to_identifier((char*)binding);
	if (! binding_s) {
		message(G_LOG_LEVEL_CRITICAL, "XXX: unknown binding: %s", binding);
		goto cleanup;
	}

	/* get endpoint location */
	value = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_LOCATION);

	if (value == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX: missing location for element %s", xmlnode->name);
		goto cleanup;
	}
	/* special case of AssertionConsumerService */
	if (checkSaml2MdNode(xmlnode, LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE)) {
		xmlChar *index = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_INDEX);
		xmlChar *is_default = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_ISDEFAULT);

		if (xsdIsTrue(is_default) && ! private_data->default_assertion_consumer) {
			lasso_assign_string(private_data->default_assertion_consumer, (char*)index);
		}
		name = g_strdup_printf(LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE 
				" %s %s", 
				binding_s,
				index);
		lasso_release_xml_string(index);
		lasso_release_xml_string(is_default);
	} else {
		name = g_strdup_printf("%s %s", xmlnode->name, binding_s);
	}
	lasso_release_xml_string(binding);

	/* Response endpoint ? */
	response_value = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_RESPONSE_LOCATION);
	if (response_value) {
		response_name = g_strdup_printf("%s "
				LASSO_SAML2_METADATA_ATTRIBUTE_RESPONSE_LOCATION,
				name);
		_lasso_provider_add_metadata_value_for_role(provider, role, response_name,
				(char*)response_value);
	}
	_lasso_provider_add_metadata_value_for_role(provider, role, name, (char*)value);

cleanup:
	lasso_release_xml_string(value);
	lasso_release_xml_string(response_value);
	lasso_release_string(name);
	lasso_release_string(response_name);
}

/*
 * Apply algorithm for find a default assertion consumer when no declared assertion consumer has the
 * isDefault attribute */
static gboolean
load_default_assertion_consumer(xmlNode *descriptor, LassoProvider *provider)
{
	xmlChar *index = NULL;
	xmlChar *is_default = NULL;
	xmlNode *t = NULL;
	LassoProviderPrivate *pdata = provider->private_data;

	g_return_val_if_fail(pdata, FALSE);
	if (provider->private_data->default_assertion_consumer) {
		return TRUE;
	}

	t = xmlSecGetNextElementNode(descriptor->children);
	while (t) {
		if (checkSaml2MdNode(t,
				LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE)) {
			lasso_release_xml_string(is_default);
			is_default = getSaml2MdProp(t, LASSO_SAML2_METADATA_ATTRIBUTE_ISDEFAULT);
			if (! xsdIsFalse(is_default)) {
				index = getSaml2MdProp(t, LASSO_SAML2_METADATA_ATTRIBUTE_INDEX);
				if (! index) {
					t = xmlSecGetNextElementNode(t->next);
					continue;
				}
				lasso_assign_string(pdata->default_assertion_consumer, (char*)index);
				lasso_release_xml_string(index);
				break;
			}
		}
		t = xmlSecGetNextElementNode(t->next);
	}
	lasso_release_xml_string(is_default);
	if (provider->private_data->default_assertion_consumer) {
		return TRUE;
	}
	t = xmlSecFindChild(descriptor,
			BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE,
			BAD_CAST LASSO_SAML2_METADATA_HREF);
	if (! t) {
		return FALSE;
	}
	index = getSaml2MdProp(t, LASSO_SAML2_METADATA_ATTRIBUTE_INDEX);
	if (! index) {
		return FALSE;
	}
	lasso_assign_string( pdata->default_assertion_consumer, (char*)index);
	lasso_release_xml_string(index);
	return TRUE;

}

static gboolean
load_descriptor(xmlNode *xmlnode, LassoProvider *provider, LassoProviderRole role)
{
	static char * const descriptor_attrs[] = {
		LASSO_SAML2_METADATA_ATTRIBUTE_VALID_UNTIL,
		LASSO_SAML2_METADATA_ATTRIBUTE_CACHE_DURATION,
		LASSO_SAML2_METADATA_ATTRIBUTE_AUTHN_REQUEST_SIGNED,
		LASSO_SAML2_METADATA_ATTRIBUTE_WANT_AUTHN_REQUEST_SIGNED,
		LASSO_SAML2_METADATA_ATTRIBUTE_ERROR_URL
	};
	int i;
	xmlNode *t;
	xmlChar *value;
	LassoProviderPrivate *pdata = provider->private_data;
	char *token, *saveptr;
	
	/* check protocol support enumeration */
	value = getSaml2MdProp(xmlnode,
			LASSO_SAML2_METADATA_ATTRIBUTE_PROTOCOL_SUPPORT_ENUMERATION);
	token = strtok_r((char*) value, " ", &saveptr);
	while (token) {
		if (strcmp(token, LASSO_SAML2_PROTOCOL_HREF) == 0)
			break;
		token = strtok_r(NULL, " ", &saveptr);
	}
	if (g_strcmp0(token, LASSO_SAML2_PROTOCOL_HREF) != 0) {
		lasso_release_xml_string(value);
		message(G_LOG_LEVEL_WARNING, "%s descriptor does not support SAML 2.0 protocol", xmlnode->name);
		return FALSE;
	}
	lasso_release_xml_string(value);

	/* add role to supported roles for the provider */
	pdata->roles |= role;
	t = xmlSecGetNextElementNode(xmlnode->children);
	while (t) {
		if (checkSaml2MdNode(t,
					LASSO_SAML2_METADATA_ELEMENT_KEY_DESCRIPTOR)) {
			_lasso_provider_load_key_descriptor(provider, t);
		} else if (checkSaml2MdNode(t,
					LASSO_SAML2_ASSERTION_ELEMENT_ATTRIBUTE) && role == LASSO_PROVIDER_ROLE_IDP) {
			LassoSaml2Attribute *attribute;
			attribute = (LassoSaml2Attribute*) lasso_node_new_from_xmlNode(t);
			lasso_list_add_new_gobject(pdata->attributes, 
					attribute);
		} else if (hasSaml2MdProp(t, LASSO_SAML2_METADATA_ATTRIBUTE_BINDING)) {
			load_endpoint_type(t, provider, role);
		} else {
			value = xmlNodeGetContent(t);
			_lasso_provider_add_metadata_value_for_role(provider, role, (char*)t->name,
					(char*)value);
			lasso_release_xml_string(value);
		}
		t = xmlSecGetNextElementNode(t->next);
	}
	for (i = 0; descriptor_attrs[i]; i++) {
		value = getSaml2MdProp(xmlnode, descriptor_attrs[i]);
		if (value == NULL) {
			continue;
		}
		_lasso_provider_add_metadata_value_for_role(provider, role, descriptor_attrs[i],
				(char*)value);
		lasso_release_xml_string(value);
	}

	if (! load_default_assertion_consumer(xmlnode, provider) && role == LASSO_PROVIDER_ROLE_SP) {
		message(G_LOG_LEVEL_WARNING, "Could not find a default assertion consumer, check the metadata file");
		return FALSE;
	}

	return TRUE;
}

gboolean
lasso_saml20_provider_load_metadata(LassoProvider *provider, xmlNode *root_node)
{
	xmlNode *node, *descriptor_node;
	xmlChar *providerID;
	LassoProviderPrivate *pdata = provider->private_data;
	static const struct {
		char *name;
		LassoProviderRole role;
	} descriptors[] = {
		{ LASSO_SAML2_METADATA_ELEMENT_IDP_SSO_DESCRIPTOR,
			LASSO_PROVIDER_ROLE_IDP },
		{ LASSO_SAML2_METADATA_ELEMENT_SP_SSO_DESCRIPTOR,
			LASSO_PROVIDER_ROLE_SP },
		{ LASSO_SAML2_METADATA_ELEMENT_ATTRIBUTE_AUTHORITY_DESCRIPTOR,
			LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY },
		{ LASSO_SAML2_METADATA_ELEMENT_PDP_DESCRIPTOR,
			LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY },
		{ LASSO_SAML2_METADATA_ELEMENT_AUTHN_DESCRIPTOR,
			LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY },
		{ NULL, 0 }
	};

	/* find a root node for the metadata file */
	if (xmlSecCheckNodeName(root_node,
			BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITY_DESCRIPTOR,
			BAD_CAST LASSO_SAML2_METADATA_HREF)) {
		node = root_node;
	} else if (xmlSecCheckNodeName(root_node,
			BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITIES_DESCRIPTOR,
			BAD_CAST LASSO_SAML2_METADATA_HREF)) {
		node = xmlSecFindChild(root_node,
				BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITY_DESCRIPTOR,
				BAD_CAST LASSO_SAML2_METADATA_HREF);
	}

	g_return_val_if_fail (node, FALSE);
	providerID = xmlGetProp(node, (xmlChar*)"entityID");
	g_return_val_if_fail(providerID, FALSE);
	lasso_assign_string(provider->ProviderID, (char*)providerID);
	lasso_release_xml_string(providerID);
	/* initialize roles */
	pdata->roles = LASSO_PROVIDER_ROLE_NONE;
	lasso_set_string_from_prop(&pdata->valid_until, node,
				BAD_CAST LASSO_SAML2_METADATA_ATTRIBUTE_VALID_UNTIL,
				BAD_CAST LASSO_SAML2_METADATA_HREF);
	lasso_set_string_from_prop(&pdata->cache_duration, node,
				BAD_CAST LASSO_SAML2_METADATA_ATTRIBUTE_CACHE_DURATION,
				BAD_CAST LASSO_SAML2_METADATA_HREF);

	descriptor_node = xmlSecGetNextElementNode(node->children);
	while (descriptor_node) {
		int i = 0;

		while (descriptors[i].name) {
			char *name = descriptors[i].name;
			LassoProviderRole role = descriptors[i].role;

			if (checkSaml2MdNode(descriptor_node, name)) {
				load_descriptor(descriptor_node,
						provider,
						role);
			}
			i++;
		}

		if (checkSaml2MdNode(descriptor_node,
					LASSO_SAML2_METADATA_ELEMENT_ORGANIZATION)) {
			lasso_assign_xml_node(pdata->organization, descriptor_node); }
		descriptor_node = xmlSecGetNextElementNode(descriptor_node->next);
	}

	return TRUE;
}

LassoHttpMethod
lasso_saml20_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type)
{
	LassoHttpMethod method = LASSO_HTTP_METHOD_NONE;
	LassoProviderRole our_role = LASSO_PROVIDER_ROLE_SP;
	int i;
	const char *possible_bindings[] = {
		"HTTP-POST",
		"HTTP-Redirect",
		"HTTP-Artifact",
		"SOAP",
		"PAOS",
		NULL
	};
	LassoHttpMethod method_bindings[] = {
		LASSO_HTTP_METHOD_POST,
		LASSO_HTTP_METHOD_REDIRECT,
		LASSO_HTTP_METHOD_ARTIFACT_GET,
		LASSO_HTTP_METHOD_SOAP,
		LASSO_HTTP_METHOD_PAOS
	};

	switch (remote_provider->role) {
		case LASSO_PROVIDER_ROLE_IDP:
			our_role = LASSO_PROVIDER_ROLE_SP;
			break;
		case LASSO_PROVIDER_ROLE_SP:
			our_role = LASSO_PROVIDER_ROLE_IDP;
			break;
		default:
			return LASSO_HTTP_METHOD_NONE;
	}
	for (i=0; possible_bindings[i] && method == LASSO_HTTP_METHOD_NONE; i++) {
		char *s;
		const GList *l1, *l2;

		s = g_strdup_printf("%s %s",
				profile_names[protocol_type],
				possible_bindings[i]);
		l1 = lasso_provider_get_metadata_list_for_role(provider, our_role, s);
		l2 = lasso_provider_get_metadata_list(remote_provider, s);
		if (l1 && l2) {
			method = method_bindings[i];
		}
	}

	return method;
}

gboolean
lasso_saml20_provider_check_assertion_consumer_service_url(LassoProvider *provider, const gchar *url, const gchar *binding)
{
	GHashTable *descriptor;
	GList *l = NULL, *r = NULL, *candidate = NULL;
	char *name;
	const char *binding_s = NULL;
	int lname;

	descriptor = provider->private_data->Descriptors;
	if (descriptor == NULL || url == NULL || binding == NULL)
		return FALSE;

	binding_s = binding_uri_to_identifier(binding);
	if (binding_s == NULL) {
		return FALSE;
	}

	g_hash_table_foreach(descriptor,
			(GHFunc)add_assertion_consumer_url_to_list,
			&r);

	name = g_strdup_printf(LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE
			" %s ", binding_s);
	lname = strlen(name);
	for (l = r; l; l = g_list_next(l)) {
		char *b = l->data;
		if (strncmp(name, b, lname) == 0) {
			candidate = lasso_provider_get_metadata_list_for_role(provider, LASSO_PROVIDER_ROLE_SP, b);
			if (candidate && candidate->data && strcmp(candidate->data, url) == 0)
				break;
			else
				candidate = NULL;
		}
	}
	lasso_release(name);
	lasso_release_list(r);

	if (candidate)
		return TRUE;
	else
		return FALSE;
}

gchar*
lasso_saml20_provider_get_assertion_consumer_service_url(LassoProvider *provider,
		int service_id)
{
	GList *l = NULL;
	char *sid;
	char *name;
	const char *possible_bindings[] = {
		"HTTP-Artifact",
		"HTTP-POST",
		NULL
	};
	int i;

	if (service_id == -1) {
		sid = g_strdup(provider->private_data->default_assertion_consumer);
	} else {
		sid = g_strdup_printf("%d", service_id);
	}

	for (i=0; possible_bindings[i]; i++) {
		name = g_strdup_printf(LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE
				" %s %s",
				possible_bindings[i], sid);
		l = lasso_provider_get_metadata_list_for_role(provider,
				LASSO_PROVIDER_ROLE_SP,
				name);
		lasso_release_string(name);
		if (l != NULL)
			break;
	}
	lasso_release_string(sid);
	if (l)
		return g_strdup(l->data);
	return NULL;
}

#define ACS_KEY "sp " LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE

static void
add_assertion_consumer_url_to_list(gchar *key, G_GNUC_UNUSED gpointer value, GList **list)
{
	if (strncmp(key, ACS_KEY, sizeof(ACS_KEY)-1) == 0) {
		lasso_list_add_new_string(*list, key);
	}
}

struct HelperBindingByUrl {
	const char *binding;
	const char *url;
};

void
helper_binding_by_url(char *key, GList *value, struct HelperBindingByUrl *data)
{
	if (strncmp(key, ACS_KEY, sizeof(ACS_KEY)-1) != 0) {
		return;
	}

	if (data->binding == NULL && g_list_find_custom(value, data->url, (GCompareFunc)g_strcmp0) != NULL) {
		char *end;
		// URL was found for the first time
		key += sizeof(ACS_KEY);
		end = strchr(key, ' ');
		if (end) {
			key = g_strndup(key, (ptrdiff_t)(end-key));
			data->binding = identifier_to_binding_uri(key);
			lasso_release(key);
		} else {
			data->binding = identifier_to_binding_uri(key);
		}
	}

}

const gchar*
lasso_saml20_provider_get_assertion_consumer_service_binding_by_url(LassoProvider *provider, const char *url)
{
	struct HelperBindingByUrl _helper_binding_by_url = { .binding = NULL, .url = url };

	g_hash_table_foreach(provider->private_data->Descriptors, (GHFunc)helper_binding_by_url,
			&_helper_binding_by_url);

	return _helper_binding_by_url.binding;
}

gchar*
lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(LassoProvider *provider,
		const gchar *binding)
{
	GHashTable *descriptor;
	GList *l = NULL, *r = NULL;
	char *name;
	const char *binding_s = NULL;
	int lname;

	descriptor = provider->private_data->Descriptors;
	if (descriptor == NULL)
		return NULL;

	binding_s = binding_uri_to_identifier(binding);
	if (binding_s == NULL) {
		return NULL;
	}

	g_hash_table_foreach(descriptor,
			(GHFunc)add_assertion_consumer_url_to_list,
			&r);

	name = g_strdup_printf("sp "
			LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE
			" %s ", binding_s);
	lname = strlen(name);
	for (l = r; l; l = g_list_next(l)) {
		char *b = l->data;
		if (strncmp(name, b, lname) == 0) {
			l = g_hash_table_lookup(descriptor, b);
			break;
		}
	}
	lasso_release_string(name);
	lasso_release_list(r);

	if (l) {
		return g_strdup(l->data);
	}

	return NULL;
}

gchar*
lasso_saml20_provider_get_assertion_consumer_service_binding(LassoProvider *provider,
		int service_id)
{
	GHashTable *descriptor;
	GList *l = NULL;
	char *sid;
	char *name;
	char *binding = NULL;
	const char *possible_bindings[] = {
		"HTTP-POST",
		"HTTP-Redirect",
		"HTTP-Artifact",
		"SOAP", 
		NULL
	};
	int i;

	if (service_id == -1) {
		sid = g_strdup(provider->private_data->default_assertion_consumer);
	} else {
		sid = g_strdup_printf("%d", service_id);
	}
	descriptor = provider->private_data->Descriptors;
	if (descriptor == NULL)
		return NULL;

	for (i=0; possible_bindings[i]; i++) {
		name = g_strdup_printf(LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE
				" %s %s",
				possible_bindings[i], sid);
		l = lasso_provider_get_metadata_list_for_role(provider, LASSO_PROVIDER_ROLE_SP, name);
		lasso_release_string(name);
		if (l != NULL) {
			binding = g_strdup(possible_bindings[i]);
			break;
		}
	}
	lasso_release_string(sid);
	return binding;
}

gboolean
lasso_saml20_provider_accept_http_method(LassoProvider *provider, LassoProvider *remote_provider,
		LassoMdProtocolType protocol_type, LassoHttpMethod http_method,
		gboolean initiate_profile)
{
	char *protocol_profile;
	static const char *http_methods[] = {
		NULL,
		NULL,
		NULL,
		NULL,
		"HTTP-POST",
		"HTTP-Redirect",
		"SOAP",
		"HTTP-Artifact",
		"HTTP-Artifact",
		NULL
	};
	gboolean rc = FALSE;
	LassoProviderRole initiating_role;

	initiating_role = remote_provider->role;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		provider->role = LASSO_PROVIDER_ROLE_SP;
	}
	if (initiate_profile)
		initiating_role = provider->role;

	/* exclude bad input */
	if (http_method > (int)G_N_ELEMENTS(http_methods) || http_method < 0 ||  http_methods[http_method+1] == NULL) {
		return FALSE;
	}

	protocol_profile = g_strdup_printf("%s %s", profile_names[protocol_type],
			http_methods[http_method+1]);

	/* just check if remote provider can receive the request, remote provider will have to check
	 * how to return the response itself */
	rc = (lasso_provider_get_metadata_list(remote_provider, protocol_profile) != NULL);
	lasso_release_string(protocol_profile);
	return rc;
}

/**
 * lasso_provider_saml2_node_encrypt:
 * @provider: a #LassoProvider object
 * @lasso_node: a #LassoNode object
 *
 * Dump the node object to an XML fragment, then encrypt this fragment using encryption key of
 * @provider, then encapsulate the resulting encrypted content into a #LassoSaml2EncryptedElement.
 *
 * Return value: a newly created #LassoSaml2EncryptedElement if successfull, NULL otherwise.
 */
LassoSaml2EncryptedElement*
lasso_provider_saml2_node_encrypt(const LassoProvider *provider, LassoNode *lasso_node)
{
	LassoSaml2EncryptedElement *saml2_encrypted_element;

	g_return_val_if_fail(LASSO_IS_PROVIDER (provider), NULL);
	g_return_val_if_fail(LASSO_IS_NODE (lasso_node), NULL);

	saml2_encrypted_element = lasso_node_encrypt(lasso_node,
			lasso_provider_get_encryption_public_key(provider),
			lasso_provider_get_encryption_sym_key_type(provider),
			provider->ProviderID);

	return saml2_encrypted_element;
}
