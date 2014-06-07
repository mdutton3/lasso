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

static void
debug_report_signature_error(xmlNode *node, lasso_error_t result) {
	xmlChar *path;

	path = xmlGetNodePath(node);
	debug("Could not check signature whose xpath is '%s': %s", path, lasso_strerror(result));
	lasso_release_xml_string(path);
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
		xmlDoc *doc, xmlNode *entity, GList *blacklisted_entity_ids, GList **loaded_end,
		xmlSecKeysMngr *keys_mngr, LassoServerLoadMetadataFlag flags)
{
	LassoProvider *provider = NULL;
	gboolean check_signature = flags & LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITY_DESCRIPTOR_SIGNATURE;

	if (role == LASSO_PROVIDER_ROLE_IDP && ! _lasso_test_idp_descriptor(entity)) {
		return 0;
	}
	if (role == LASSO_PROVIDER_ROLE_SP && ! _lasso_test_sp_descriptor(entity)) {
		return 0;
	}

	if (keys_mngr && check_signature) {
		lasso_error_t result;

		result = lasso_verify_signature(entity, doc, "ID", keys_mngr, NULL, EMPTY_URI,
				NULL);
		if (result != 0) {
			debug_report_signature_error(entity, result);
			return result;
		}
	}

	provider = lasso_provider_new_from_xmlnode(role, entity);
	if (provider) {
		char *name = provider->ProviderID;

		if (g_list_find_custom(blacklisted_entity_ids, name,
					(GCompareFunc) g_strcmp0)) {
			lasso_release_gobject(provider);
			return LASSO_SERVER_ERROR_NO_PROVIDER_LOADED;
		}
		if (loaded_end) {
			*loaded_end = g_list_prepend(*loaded_end, g_strdup(name));
		}
		g_hash_table_insert(server->providers, g_strdup(name), provider);
		return 0;
	} else {
		return LASSO_SERVER_ERROR_NO_PROVIDER_LOADED;
	}
}

static lasso_error_t lasso_saml20_server_load_metadata_child(LassoServer *server,
		LassoProviderRole role, xmlDoc *doc, xmlNode *child, GList *blacklisted_entity_ids,
		GList **loaded_end, xmlSecKeysMngr *keys_mngr, LassoServerLoadMetadataFlag flags);

static lasso_error_t
lasso_saml20_server_load_metadata_entities(LassoServer *server, LassoProviderRole role, xmlDoc *doc, xmlNode *entities,
		GList *blacklisted_entity_ids, GList **loaded_end,
		xmlSecKeysMngr *keys_mngr, LassoServerLoadMetadataFlag flags)
{
	xmlNode *child;
	gboolean at_least_one = FALSE;
	gboolean check_signature = flags & LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITIES_DESCRIPTOR_SIGNATURE;
	gboolean inherit_signature = flags & LASSO_SERVER_LOAD_METADATA_FLAG_INHERIT_SIGNATURE;

	/* if a key store is passed, check signature */
	if (keys_mngr && check_signature) {
		lasso_error_t result;

		result = lasso_verify_signature(entities, doc, "ID", keys_mngr, NULL, EMPTY_URI,
				NULL);
		if (result == 0) {
			if (inherit_signature) {
				keys_mngr = NULL;
			}
		} else {
			debug_report_signature_error(entities, result);
			return result;
		}
	}

	child = xmlSecGetNextElementNode(entities->children);
	while (child) {
		lasso_error_t rc = 0;

		rc = lasso_saml20_server_load_metadata_child(server, role, doc, child,
				blacklisted_entity_ids, loaded_end, keys_mngr, flags);
		if (rc == 0) {
			at_least_one = TRUE;
		}
		child = xmlSecGetNextElementNode(child->next);
	}
	return at_least_one ? 0 : LASSO_SERVER_ERROR_NO_PROVIDER_LOADED;
}

static lasso_error_t
lasso_saml20_server_load_metadata_child(LassoServer *server, LassoProviderRole role, xmlDoc *doc,
		xmlNode *child, GList *blacklisted_entity_ids, GList **loaded_end,
		xmlSecKeysMngr *keys_mngr, LassoServerLoadMetadataFlag flags)
{
	if (xmlSecCheckNodeName(child,
				BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITY_DESCRIPTOR,
				BAD_CAST LASSO_SAML2_METADATA_HREF)) {
		return lasso_saml20_server_load_metadata_entity(server, role, doc, child,
				blacklisted_entity_ids, loaded_end, keys_mngr, flags);
	} else if (xmlSecCheckNodeName(child,
				BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITIES_DESCRIPTOR,
				BAD_CAST LASSO_SAML2_METADATA_HREF)) {
		return lasso_saml20_server_load_metadata_entities(server, role, doc, child,
				blacklisted_entity_ids, loaded_end, keys_mngr, flags);
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
lasso_saml20_server_load_metadata(LassoServer *server, LassoProviderRole role,
		xmlDoc *doc, xmlNode *root_node,
		GList *blacklisted_entity_ids, GList **loaded_entity_ids,
		xmlSecKeysMngr *keys_mngr, LassoServerLoadMetadataFlag flags)
{
	lasso_error_t rc = 0;
	GList *loaded = NULL;
	GList **loaded_end = NULL;

	if (loaded_entity_ids) {
		loaded_end = &loaded;
	}
	rc = lasso_saml20_server_load_metadata_child(server, role,
			doc, root_node, blacklisted_entity_ids, loaded_end, keys_mngr, flags);
	if (loaded_entity_ids) {
		loaded = g_list_reverse(loaded);
		lasso_release_list_of_strings(*loaded_entity_ids);
		*loaded_entity_ids = loaded;
	}
	return rc;
}
