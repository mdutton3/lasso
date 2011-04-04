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

#include <xmlsec/xmltree.h>

#include "../utils.h"
#include "../xml/private.h"
#include "serverprivate.h"
#include "../id-ff/serverprivate.h"
#include "../id-ff/providerprivate.h"
#include "../xml/saml-2.0/saml2_xsd.h"


int
lasso_saml20_server_load_affiliation(LassoServer *server, xmlNode *node)
{
	xmlNode *t;
	char *owner_id, *member_id, *affiliation_id;
	LassoProvider *provider;

	if (strcmp((char*)node->ns->href, LASSO_SAML2_METADATA_HREF) != 0) {
		/* not saml 2 metadata ns */
		return LASSO_XML_ERROR_NODE_NOT_FOUND;
	}

	for (t = node->children; t; t = t->next) {
		if (t->type == XML_ELEMENT_NODE &&
				strcmp((char*)t->name, "AffiliationDescriptor") == 0) {
			break;
		}
	}

	if (t == NULL) {
		/* no AffiliationDescriptor element */
		return LASSO_XML_ERROR_NODE_NOT_FOUND;
	}

	affiliation_id = (char*)xmlGetProp(node, (xmlChar*)"entityID");
	owner_id = (char*)xmlGetProp(t, (xmlChar*)"affiliationOwnerID");

	for (t = t->children; t; t = t->next) {
		if (t->type == XML_ELEMENT_NODE &&
				strcmp((char*)t->name, "AffiliateMember") == 0) {
			member_id = (char*)xmlNodeGetContent(t);
			provider = lasso_server_get_provider(server, member_id);
			if (provider == NULL) {
				message(G_LOG_LEVEL_WARNING,
						"Failed to find affiliate member: %s", member_id);
				xmlFree(member_id);
				continue;
			}
			if (provider->private_data->affiliation_owner_id) {
				message(G_LOG_LEVEL_WARNING,
						"Provider %s in more than one affiliation",
						provider->ProviderID);
				lasso_release_string(provider->private_data->affiliation_owner_id);
			}
			provider->private_data->affiliation_owner_id = g_strdup(owner_id);
			provider->private_data->affiliation_id = g_strdup(affiliation_id);
			xmlFree(member_id);
		}
	}

	xmlFree(affiliation_id);
	xmlFree(owner_id);

	return 0;
}

static gboolean
_lasso_test_sp_descriptor(xmlNode *node) {
	return xmlSecFindChild(node,
			BAD_CAST LASSO_SAML2_METADATA_ELEMENT_SP_SSO_DESCRIPTOR,
			BAD_CAST LASSO_SAML2_METADATA_HREF) != NULL;
}

static gboolean
_lasso_test_idp_descriptor(xmlNode *node) {
	return xmlSecFindChild(node,
			BAD_CAST LASSO_SAML2_METADATA_ELEMENT_IDP_SSO_DESCRIPTOR,
			BAD_CAST LASSO_SAML2_METADATA_HREF) != NULL;
}

static lasso_error_t
lasso_saml20_server_load_metadata_entity(LassoServer *server, LassoProviderRole role,
		xmlNode *entity, GList *blacklisted_entity_ids, GList **loaded_end)
{
	LassoProvider *provider = NULL;

	if (role == LASSO_PROVIDER_ROLE_IDP && ! _lasso_test_idp_descriptor(entity)) {
		return 0;
	}
	if (role == LASSO_PROVIDER_ROLE_SP && ! _lasso_test_sp_descriptor(entity)) {
		return 0;
	}

	provider = lasso_provider_new_from_xmlnode(role, entity);
	if (provider) {
		char *name = g_strdup(provider->ProviderID);

		if (g_list_find_custom(blacklisted_entity_ids, name,
					(GCompareFunc) g_strcmp0)) {
			lasso_release_gobject(provider);
			return LASSO_SERVER_ERROR_NO_PROVIDER_LOADED;
		}
		if (*loaded_end) {
			GList *l = *loaded_end;
			l->next = g_new0(GList, 1);
			l->next->data = g_strdup(name);
			*loaded_end = l->next;
		}
		g_hash_table_insert(server->providers, name, provider);
		return 0;
	} else {
		return LASSO_SERVER_ERROR_NO_PROVIDER_LOADED;
	}
}

static lasso_error_t lasso_saml20_server_load_metadata_child(LassoServer *server,
		LassoProviderRole role, xmlNode *child, GList *blacklisted_entity_ids,
		GList **loaded_end);

static lasso_error_t
lasso_saml20_server_load_metadata_entities(LassoServer *server, LassoProviderRole role, xmlNode *entities,
		GList *blacklisted_entity_ids, GList **loaded_end)
{
	xmlNode *child;
	gboolean at_least_one = FALSE;

	child = xmlSecGetNextElementNode(entities->children);
	while (child) {
		lasso_error_t rc = 0;

		rc = lasso_saml20_server_load_metadata_child(server, role, child,
				blacklisted_entity_ids, loaded_end);
		if (rc == 0) {
			at_least_one = TRUE;
		}
		child = xmlSecGetNextElementNode(child->next);
	}
	return at_least_one ? 0 : LASSO_SERVER_ERROR_NO_PROVIDER_LOADED;
}

static lasso_error_t
lasso_saml20_server_load_metadata_child(LassoServer *server, LassoProviderRole role, xmlNode *child,
		GList *blacklisted_entity_ids, GList **loaded_end)
{
	if (xmlSecCheckNodeName(child,
				BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITY_DESCRIPTOR,
				BAD_CAST LASSO_SAML2_METADATA_HREF)) {
		return lasso_saml20_server_load_metadata_entity(server, role, child,
				blacklisted_entity_ids, loaded_end);
	} else if (xmlSecCheckNodeName(child,
				BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITIES_DESCRIPTOR,
				BAD_CAST LASSO_SAML2_METADATA_HREF)) {
		return lasso_saml20_server_load_metadata_entities(server, role, child,
				blacklisted_entity_ids, loaded_end);
	}
	return LASSO_SERVER_ERROR_INVALID_XML;
}

/**
 * lasso_saml20_server_load_metadata:
 * @server: a #LassoServer object
 * @role: the role of providers to load
 * @root_node: the root node a SAML 2.0 metadata file
 * @blacklisted_entity_ids: a list of entity IDs of provider to skip
 * @loaded_entity_ids: an out parameter to return the list of the loaded providers entity IDs
 *
 * Load the SAML 2.0 providers present in the given metadata as pointed to by the @root_node
 * parameter. If at least one provider is loaded the call is deemed successful.
 *
 * Return value: 0 if at least one provider has been loaded, LASSO_SERVER_ERROR_NO_PROVIDER_LOADED
 * otherwise.
 */
lasso_error_t
lasso_saml20_server_load_metadata(LassoServer *server, LassoProviderRole role, xmlNode *root_node,
		GList *blacklisted_entity_ids, GList **loaded_entity_ids)
{
	lasso_error_t rc = 0;
	GList loaded = { .data = NULL, .next = NULL };
	GList *loaded_end = NULL;

	if (loaded_entity_ids) {
		loaded_end = &loaded;
	}
	rc = lasso_saml20_server_load_metadata_child(server, role,
			root_node, blacklisted_entity_ids, &loaded_end);
	if (loaded_entity_ids) {
		lasso_release_list_of_strings(*loaded_entity_ids);
		*loaded_entity_ids = loaded.next;
	}
	return rc;
}
