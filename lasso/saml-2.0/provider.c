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

#include <xmlsec/base64.h>

#include <lasso/saml-2.0/providerprivate.h>
#include <lasso/id-ff/providerprivate.h>

const char *profile_names[] = {
	"", /* No fedterm in SAML 2.0 */
	"NameIDMappingService",
	"", /* No rni in SAML 2.0 */
	"SingleLogoutService",
	"SingleSignOnService",
	"ArtifactResolutionService",
	"ManageNameIDService",
	"AssertionIDRequestService",
	NULL
};

static void
load_descriptor(xmlNode *xmlnode, GHashTable *descriptor, LassoProvider *provider)
{
	char *descriptor_attrs[] = {"AuthnRequestsSigned", "WantAuthnRequestsSigned", NULL};
	int i;
	xmlNode *t;
	GList *elements;
	char *name, *binding, *response_name;
	xmlChar *value, *response_value;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp((char*)t->name, "KeyDescriptor") == 0) {
			char *use = (char*)xmlGetProp(t, (xmlChar*)"use");
			if (use && strcmp(use, "signing") == 0) {
				provider->private_data->signing_key_descriptor = xmlCopyNode(t, 1);
			}
			if (use && strcmp(use, "encryption") == 0) {
				provider->private_data->encryption_key_descriptor = 
					xmlCopyNode(t, 1);
			}
			t = t->next;
			continue;
		}
		binding = (char*)xmlGetProp(t, (xmlChar*)"Binding");
		if (binding) {
			/* Endpoint type */
			char *binding_s = NULL;
			if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_SOAP) == 0) {
				binding_s = "SOAP";
			} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_REDIRECT) == 0) {
				binding_s = "HTTP-Redirect";
			} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_POST) == 0) {
				binding_s = "HTTP-POST";
			} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_ARTIFACT) == 0) {
				binding_s = "HTTP-Artifact";
			} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_PAOS) == 0) {
				binding_s = "PAOS";
			} else {
				message(G_LOG_LEVEL_CRITICAL, "XXX: unknown binding: %s", binding);
				xmlFree(binding);
				t = t->next;
				continue;
			}
			value = xmlGetProp(t, (xmlChar*)"Location");
			if (value == NULL) {
				message(G_LOG_LEVEL_CRITICAL, "XXX: missing location");
				xmlFree(binding);
				t = t->next;
				continue;
			}
			if (strcmp((char*)t->name, "AssertionConsumerService") == 0) {
				char *index = (char*)xmlGetProp(t, (xmlChar*)"index");
				char *is_default = (char*)xmlGetProp(t, (xmlChar*)"isDefault");
				if (is_default && strcmp(is_default, "true") == 0) {
					provider->private_data->default_assertion_consumer =
						g_strdup(index);
				}
				name = g_strdup_printf("%s %s %s", t->name, binding_s, index);
				xmlFree(index);
				xmlFree(is_default);
			} else {
				name = g_strdup_printf("%s %s", t->name, binding_s);
			}
			xmlFree(binding);

			response_value = xmlGetProp(t, (xmlChar*)"ResponseLocation");
			if (response_value) {
				response_name = g_strdup_printf("%s ResponseLocation", name);
				elements = g_hash_table_lookup(descriptor, response_name);
				elements = g_list_append(elements, g_strdup((char*)response_value));
				g_hash_table_insert(descriptor, response_name, elements);
				xmlFree(response_value);
			}
		} else {
			name = g_strdup((char*)t->name);
			value = xmlNodeGetContent(t);
		}
		elements = g_hash_table_lookup(descriptor, name);
		elements = g_list_append(elements, g_strdup((char*)value));
		xmlFree(value);
		g_hash_table_insert(descriptor, name, elements);
		t = t->next;
	}

	for (i=0; descriptor_attrs[i]; i++) {
		value = xmlGetProp(xmlnode, (xmlChar*)descriptor_attrs[i]);
		if (value == NULL) continue;

		name = g_strdup(descriptor_attrs[i]);
		elements = g_hash_table_lookup(descriptor, name);
		elements = g_list_append(elements, g_strdup((char*)value));
		xmlFree(value);
		g_hash_table_insert(descriptor, name, elements);
	}

}

gboolean
lasso_saml20_provider_load_metadata(LassoProvider *provider, xmlNode *root_node)
{
	xmlNode *node, *descriptor_node;

	if (strcmp((char*)root_node->name, "EntityDescriptor") == 0) {
		node = root_node;
	} else if (strcmp((char*)root_node->name, "EntitiesDescriptor") == 0) {
		/* XXX: take the first entity; would it be possible to have an
		 * optional argument to take another one ? */
		node = root_node->children;
		while (node && strcmp((char*)node->name, "EntityDescriptor") != 0) {
			node = node->next;
		}
		if (node == NULL)
			return FALSE;
	} else {
		/* what? */
		return FALSE;
	}

	provider->ProviderID = (char*)xmlGetProp(node, (xmlChar*)"entityID");
	if (provider->ProviderID == NULL)
		return FALSE;

	for (descriptor_node = node->children; descriptor_node != NULL;
			descriptor_node = descriptor_node->next) {
		if (descriptor_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char*)descriptor_node->name, "IDPSSODescriptor") == 0) {
			load_descriptor(descriptor_node,
					provider->private_data->IDPDescriptor, provider);
			provider->role = LASSO_PROVIDER_ROLE_IDP;
			continue;
		}

		if (strcmp((char*)descriptor_node->name, "SPSSODescriptor") == 0) {
			load_descriptor(descriptor_node,
					provider->private_data->SPDescriptor, provider);
			provider->role = LASSO_PROVIDER_ROLE_SP;
			continue;
		}

		if (strcmp((char*)descriptor_node->name, "Organization") == 0) {
			provider->private_data->organization = xmlCopyNode(
					descriptor_node, 1);
			continue;
		}
	}



	return TRUE;
}

LassoHttpMethod
lasso_saml20_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type)
{
	LassoHttpMethod method = LASSO_HTTP_METHOD_NONE;
	int i;
	const char *possible_bindings[] = {
		"HTTP-Redirect", "HTTP-Post", "SOAP", NULL
	};
	LassoHttpMethod method_bindings[] = {
		LASSO_HTTP_METHOD_SOAP, LASSO_HTTP_METHOD_REDIRECT, LASSO_HTTP_METHOD_POST
	};
			
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP)
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP)
		provider->role = LASSO_PROVIDER_ROLE_SP;

	for (i=0; possible_bindings[i] && method == LASSO_HTTP_METHOD_NONE; i++) {
		char *s;
		GList *l1, *l2;

		s = g_strdup_printf("%s %s", profile_names[protocol_type], possible_bindings[i]);
		l1 = lasso_provider_get_metadata_list(provider, s);
		l2 = lasso_provider_get_metadata_list(remote_provider, s);
		if (l1 && l2) {
			method = method_bindings[i];
		}
	}

	return method;
}

gchar*
lasso_saml20_provider_get_assertion_consumer_service_url(LassoProvider *provider,
		int service_id)
{
	GHashTable *descriptor;
	GList *l = NULL;
	char *sid;
	char *name;
	const char *possible_bindings[] = {
		"HTTP-Artifact", "HTTP-Post", "HTTP-POST", "SOAP", NULL
	};
	int i;

	if (service_id == -1) {
		sid = g_strdup(provider->private_data->default_assertion_consumer);
	} else {
		sid = g_strdup_printf("%d", service_id);
	}

	descriptor = provider->private_data->SPDescriptor;
	if (descriptor == NULL)
		return NULL;

	for (i=0; possible_bindings[i]; i++) {
		name = g_strdup_printf("AssertionConsumerService %s %s",
				possible_bindings[i], sid);
		l = g_hash_table_lookup(descriptor, name);
		g_free(name);
		if (l != NULL)
			break;
	}
	g_free(sid);
	if (l)
		return g_strdup(l->data);
	return NULL;
}

static void
add_assertion_consumer_url_to_list(gchar *key, gpointer value, GList **list)
{
	if (strncmp(key, "AssertionConsumerService", 24) == 0) {
		*list = g_list_append(*list, key);
	}
}


gchar*
lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(LassoProvider *provider,
		gchar *binding)
{
	GHashTable *descriptor;
	GList *l = NULL, *r = NULL;
	char *sid;
	char *name;
	char *binding_s;
	const char *possible_bindings[] = {
		"HTTP-Artifact", "HTTP-Post", "HTTP-POST", "SOAP", NULL
	};
	int i;
	int lname;

	descriptor = provider->private_data->SPDescriptor;
	if (descriptor == NULL)
		return NULL;

	if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_SOAP) == 0) {
		binding_s = "SOAP";
	} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_REDIRECT) == 0) {
		binding_s = "HTTP-Redirect";
	} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_POST) == 0) {
		binding_s = "HTTP-POST";
	} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_ARTIFACT) == 0) {
		binding_s = "HTTP-Artifact";
	} else if (strcmp(binding, LASSO_SAML2_METADATA_BINDING_PAOS) == 0) {
		binding_s = "PAOS";
	}

	if (binding_s == NULL) {
		return NULL;
	}

	g_hash_table_foreach(descriptor, (GHFunc)add_assertion_consumer_url_to_list, &r);

	name = g_strdup_printf("AssertionConsumerService %s ", binding_s);
	lname = strlen(name);
	for (l = r; l; l = g_list_next(l)) {
		char *b = l->data;
		if (strncmp(name, b, lname) == 0) {
			l = g_hash_table_lookup(descriptor, b);
			break;
		}
	}
	g_free(name);
	g_list_free(r);

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
		"HTTP-Artifact", "HTTP-Post", "HTTP-POST", "SOAP", NULL
	};
	int i;

	if (service_id == -1) {
		sid = g_strdup(provider->private_data->default_assertion_consumer);
	} else {
		sid = g_strdup_printf("%d", service_id);
	}

	descriptor = provider->private_data->SPDescriptor;
	if (descriptor == NULL)
		return NULL;

	for (i=0; possible_bindings[i]; i++) {
		name = g_strdup_printf("AssertionConsumerService %s %s",
				possible_bindings[i], sid);
		l = g_hash_table_lookup(descriptor, name);
		g_free(name);
		if (l != NULL) {
			binding = g_strdup(possible_bindings[i]);
			break;
		}
	}
	g_free(sid);
	return binding;
}



gboolean
lasso_saml20_provider_accept_http_method(LassoProvider *provider, LassoProvider *remote_provider,
		LassoMdProtocolType protocol_type, LassoHttpMethod http_method,
		gboolean initiate_profile)
{       
	LassoProviderRole initiating_role;
	char *protocol_profile;
	char *http_methods[] = {
		NULL,
		NULL,
		NULL,
		NULL,
		"HTTP-Post",
		"HTTP-Redirect",
		"SOAP",
		"HTTP-Artifact",
		NULL
	};


	initiating_role = remote_provider->role;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		provider->role = LASSO_PROVIDER_ROLE_IDP;
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		provider->role = LASSO_PROVIDER_ROLE_SP;
	}
	if (initiate_profile)
		initiating_role = provider->role;

	protocol_profile = g_strdup_printf("%s %s", profile_names[protocol_type],
			http_methods[http_method+1]);

	if (lasso_provider_get_metadata_list(provider, protocol_profile) &&
			lasso_provider_get_metadata_list(remote_provider, protocol_profile)) {
		return TRUE;
	}

	return FALSE;
}


