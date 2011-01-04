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

#include <errno.h>

#include "../xml/private.h"
#include <xmlsec/base64.h>
#include <xmlsec/xmltree.h>

#include "providerprivate.h"
#include "../id-ff/server.h"
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

static LassoHttpMethod
binding_uri_to_http_method(const char *uri)
{
	if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_SOAP) == 0) {
		return LASSO_HTTP_METHOD_SOAP;
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_REDIRECT) == 0) {
		return LASSO_HTTP_METHOD_REDIRECT;
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_POST) == 0) {
		return LASSO_HTTP_METHOD_POST;
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_ARTIFACT) == 0) {
		return LASSO_HTTP_METHOD_ARTIFACT_GET;
	} else if (strcmp(uri, LASSO_SAML2_METADATA_BINDING_PAOS) == 0) {
		return LASSO_HTTP_METHOD_PAOS;
	}
	return LASSO_HTTP_METHOD_NONE;
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

static gboolean
xsdUnsignedShortParse(xmlChar *value, int *out) {
	int l = 0;

	errno = 0;
	l = strtol((char*)value, NULL, 10);
	if (((l == LONG_MIN || l == LONG_MAX) && errno == ERANGE) ||
			errno == EINVAL || l < 0 || l >= 65535) {
		return FALSE;
	}
	*out = l;
	return TRUE;
}

static void
load_endpoint_type2(xmlNode *xmlnode, LassoProvider *provider, LassoProviderRole role, int *counter)
{
	xmlChar *binding = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_BINDING);
	xmlChar *location = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_LOCATION);
	xmlChar *response_location = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_RESPONSE_LOCATION);
	xmlChar *index = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_INDEX);
	xmlChar *isDefault = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_ISDEFAULT);
	gboolean indexed_endpoint = FALSE;
	int idx = *counter++;
	int is_default = 0;
	EndpointType *endpoint_type;

	if (! binding || ! location) {
		warning("Invalid endpoint node %s", (char*) xmlnode->name);
		goto cleanup;
	}
	indexed_endpoint = checkSaml2MdNode(xmlnode, LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE);
	if (indexed_endpoint) {
		if (! xsdUnsignedShortParse(index, &idx)) {
			warning("Invalid AssertionConsumerService, no index set");
			goto cleanup;
		}
		/* isDefault is 0 if invalid or not present
		 * -1 if true (comes first)
		 * +1 if false (comes last)
		 */
		if (isDefault) {
			if (xsdIsTrue(isDefault)) {
				is_default = -1;
			}
			if (xsdIsFalse(isDefault)) {
				is_default = 1;
			}
		}
	}
	endpoint_type = g_new0(EndpointType, 1);
	endpoint_type->kind = g_strdup((char*)xmlnode->name);
	endpoint_type->binding = g_strdup((char*)binding);
	endpoint_type->url = g_strdup((char*)location);
	endpoint_type->return_url = g_strdup((char*)response_location);
	endpoint_type->role = role;
	endpoint_type->index = idx;
	endpoint_type->is_default = is_default;
	lasso_list_add(provider->private_data->endpoints, (void*)endpoint_type);

cleanup:
	lasso_release_xml_string(binding);
	lasso_release_xml_string(location);
	lasso_release_xml_string(response_location);
	lasso_release_xml_string(isDefault);
	lasso_release_xml_string(index);
}

static gint
compare_endpoint_type(const EndpointType *a, const EndpointType *b) {
	int c;
	
	/* order the sequence of endpoints:
	 * - first by role,
	 * - then by profile,
	 * - then by isDefault attribute (truth first, then absent, then false)
	 * - then by index
	 * - then by binding
	 */
	if (a->role < b->role)
		return -1;
	if (a->role > b->role)
		return +1;
	c = g_strcmp0(a->kind,b->kind);
	if (c != 0)
		return c;
	if (a->is_default < b->is_default)
		return -1;
	if (a->is_default > b->is_default)
		return +1;
	if (a->index < b->index)
		return -1;
	if (a->index > b->index)
		return +1;
	return 0;
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
		debug("Endpoint loading failed, unknown binding: %s", binding);
		goto cleanup;
	}

	/* get endpoint location */
	value = getSaml2MdProp(xmlnode, LASSO_SAML2_METADATA_ATTRIBUTE_LOCATION);

	if (value == NULL) {
		debug("Endpoint loading failed, missing location on element %s", xmlnode->name);
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
	int counter = 0;
	
	/* check protocol support enumeration */
	value = getSaml2MdProp(xmlnode,
			LASSO_SAML2_METADATA_ATTRIBUTE_PROTOCOL_SUPPORT_ENUMERATION);
	token = strtok_r((char*) value, " ", &saveptr);
	while (token) {
		if (strcmp(token, LASSO_SAML2_PROTOCOL_HREF) == 0)
			break;
		token = strtok_r(NULL, " ", &saveptr);
	}
	if (lasso_strisnotequal(token,LASSO_SAML2_PROTOCOL_HREF)) {
		lasso_release_xml_string(value);
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
			load_endpoint_type2(t, provider, role, &counter);
		} else {
			value = xmlNodeGetContent(t);
			_lasso_provider_add_metadata_value_for_role(provider, role, (char*)t->name,
					(char*)value);
			lasso_release_xml_string(value);
		}
		t = xmlSecGetNextElementNode(t->next);
	}
	provider->private_data->endpoints = g_list_sort(provider->private_data->endpoints,
			(GCompareFunc) compare_endpoint_type);
	for (i = 0; descriptor_attrs[i]; i++) {
		value = getSaml2MdProp(xmlnode, descriptor_attrs[i]);
		if (value == NULL) {
			continue;
		}
		_lasso_provider_add_metadata_value_for_role(provider, role, descriptor_attrs[i],
				(char*)value);
		lasso_release_xml_string(value);
	}

	if (! load_default_assertion_consumer(xmlnode, provider) && role == LASSO_PROVIDER_ROLE_SP)
	{
		message(G_LOG_LEVEL_WARNING, "Could not find a default assertion consumer, "
				"check the metadata file");
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
	gboolean loaded_one_or_more_descriptor = FALSE;

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
				loaded_one_or_more_descriptor |=
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

	if (! LASSO_IS_SERVER(provider) &&
			(! loaded_one_or_more_descriptor || (pdata->roles & provider->role) == 0)) {
		/* We must at least load one descriptor, and we must load a descriptor for our
		 * assigned role or we fail. */
		if (! loaded_one_or_more_descriptor) {
			warning("No descriptor was loaded, failing");
		}
		if ((pdata->roles & provider->role) == 0) {
			warning("Loaded roles and prescribed role does not intersect");
		}
		return FALSE;
	}

	return TRUE;
}

LassoHttpMethod
lasso_saml20_provider_get_first_http_method(G_GNUC_UNUSED LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type)
{
	GList *t = NULL;
	const char *kind = NULL;
	LassoHttpMethod result = LASSO_HTTP_METHOD_NONE;
	
	if (protocol_type < LASSO_MD_PROTOCOL_TYPE_LAST) {
		kind = profile_names[protocol_type];
	}
	if (! kind) {
		return LASSO_HTTP_METHOD_NONE;
	}

	lasso_foreach(t, remote_provider->private_data->endpoints) {
		EndpointType *endpoint_type = (EndpointType*)t->data;
		if (endpoint_type && lasso_strisequal(endpoint_type->kind, kind)) {
			result = binding_uri_to_http_method(endpoint_type->binding);
			if (result != LASSO_HTTP_METHOD_NONE)
				break;
		}
	}

	return result;
}

gboolean
lasso_saml20_provider_accept_http_method(G_GNUC_UNUSED LassoProvider *provider, LassoProvider *remote_provider,
		LassoMdProtocolType protocol_type, LassoHttpMethod http_method,
		G_GNUC_UNUSED gboolean initiate_profile)
{
	GList *t = NULL;
	const char *kind = NULL;
	
	if (protocol_type < LASSO_MD_PROTOCOL_TYPE_LAST) {
		kind = profile_names[protocol_type];
	}
	if (! kind) {
		warning("Could not find a first http method for protocol type %u", protocol_type);
		return FALSE;
	}

	lasso_foreach(t, remote_provider->private_data->endpoints) {
		EndpointType *endpoint_type = (EndpointType*)t->data;
		if (endpoint_type && endpoint_type->role == remote_provider->role &&
				lasso_strisequal(endpoint_type->kind, kind)) {
			if (binding_uri_to_http_method(endpoint_type->binding) == http_method) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

gboolean
lasso_saml20_provider_check_assertion_consumer_service_url(LassoProvider *provider, const gchar *url, const gchar *binding)
{
	GList *t = NULL;

	lasso_foreach (t, provider->private_data->endpoints) {
		EndpointType *endpoint_type = (EndpointType*) t->data;
		if (endpoint_type && endpoint_type->role == LASSO_PROVIDER_ROLE_SP
				&& lasso_strisequal(endpoint_type->url,url)
				&& lasso_strisequal(endpoint_type->binding,binding))
		{
			return TRUE;
		}
	}
	return FALSE;
}

static const char *supported_assertion_consumer_bindings[] = { LASSO_SAML2_METADATA_BINDING_POST,
	LASSO_SAML2_METADATA_BINDING_ARTIFACT, NULL };

static gboolean match_any(const char *key, const char *array[]) {
	const char **t = array;

	while (*t) {
		if (lasso_strisequal(key,*t)) {
			return TRUE;
		}
		t++;
	}
	return FALSE;
}

static EndpointType *
lasso_saml20_provider_get_assertion_consumer_service(LassoProvider *provider, int service_id)
{
	const char *kind = LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE;
	GList *t = NULL;
	EndpointType *result = NULL;

	if (service_id != -1) {
		lasso_foreach(t, provider->private_data->endpoints) {
			EndpointType *endpoint_type = (EndpointType*) t->data;
			if (! endpoint_type)
				continue;
			if (endpoint_type->role == LASSO_PROVIDER_ROLE_SP &&
					lasso_strisequal(endpoint_type->kind,kind) &&
					endpoint_type->index == service_id)
			{
				result = endpoint_type;
				break;
			}
		}
	} else { /* lookup a default supported endpoint type */
		lasso_foreach(t, provider->private_data->endpoints) {
			EndpointType *endpoint_type = (EndpointType*) t->data;
			if (! endpoint_type)
				continue;
			if (endpoint_type->role == LASSO_PROVIDER_ROLE_SP &&
					lasso_strisequal(endpoint_type->kind,kind) &&
					match_any(endpoint_type->binding,
						supported_assertion_consumer_bindings))
			{
				result = endpoint_type;
				break;
			}
		}
	}
	return result;
}


gchar*
lasso_saml20_provider_get_assertion_consumer_service_url(LassoProvider *provider,
		int service_id)
{
	EndpointType *endpoint_type = lasso_saml20_provider_get_assertion_consumer_service(provider, service_id);
	if (endpoint_type)
	{
		return g_strdup(endpoint_type->url);
	}
	return NULL;
}

gchar*
lasso_saml20_provider_get_assertion_consumer_service_binding(LassoProvider *provider,
		int service_id)
{
	EndpointType *endpoint_type = lasso_saml20_provider_get_assertion_consumer_service(provider, service_id);
	if (endpoint_type)
	{
		return g_strdup(binding_uri_to_identifier(endpoint_type->binding));
	}
	return NULL;
}

const gchar*
lasso_saml20_provider_get_assertion_consumer_service_binding_by_url(LassoProvider *provider, const char *url)
{
	const char *kind = LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE;
	GList *t = NULL;

	lasso_foreach(t, provider->private_data->endpoints) {
		EndpointType *endpoint_type = (EndpointType*) t->data;
		if (! endpoint_type)
			continue;
		if (endpoint_type->role == LASSO_PROVIDER_ROLE_SP &&
				lasso_strisequal(endpoint_type->kind,kind) &&
				lasso_strisequal(endpoint_type->url,url))
		{
			return endpoint_type->binding;
		}
	}
	return NULL;
}

gchar*
lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(LassoProvider *provider,
		const gchar *binding)
{
	const char *kind = LASSO_SAML2_METADATA_ELEMENT_ASSERTION_CONSUMER_SERVICE;
	GList *t = NULL;

	lasso_foreach(t, provider->private_data->endpoints) {
		EndpointType *endpoint_type = (EndpointType*) t->data;
		if (! endpoint_type)
			continue;
		if (endpoint_type->role == LASSO_PROVIDER_ROLE_SP &&
				lasso_strisequal(endpoint_type->kind,kind) &&
				lasso_strisequal(endpoint_type->binding,binding))
		{
			return g_strdup(endpoint_type->url);
		}
	}
	return NULL;
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
