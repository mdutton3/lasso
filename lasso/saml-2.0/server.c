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

lasso_error_t
lasso_saml20_server_load_federation(LassoServer *server, LassoProviderRole role, xmlNode *root_node, GList *blacklisted_entity_ids)
{
	xmlNode *child;
	lasso_error_t rc = 0;

	child = xmlSecGetNextElementNode(root_node->children);
	/* first parse the providers... */
	while (child) {
		LassoProvider *provider = NULL;

		if (! xmlSecCheckNodeName(child,
					BAD_CAST LASSO_SAML2_METADATA_ELEMENT_ENTITY_DESCRIPTOR,
					BAD_CAST LASSO_SAML2_METADATA_HREF)) {
			goto next;
		}
		if (role == LASSO_PROVIDER_ROLE_IDP && ! _lasso_test_idp_descriptor(child)) {
			goto next;
		}
		if (role == LASSO_PROVIDER_ROLE_SP && ! _lasso_test_sp_descriptor(child)) {
			goto next;
		}

		provider = lasso_provider_new_from_xmlnode(role, child);
		if (provider) {
			char *name = g_strdup(provider->ProviderID);

			if (g_list_find_custom(blacklisted_entity_ids, name,
						(GCompareFunc) g_strcmp0)) {
				lasso_release_gobject(provider);
				goto next;
			}
			g_hash_table_insert(server->providers, name, provider);
		}
next:
		child = xmlSecGetNextElementNode(child->next);
	}
	return rc;
}
