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
 * SECTION:identity
 * @short_description: Principal identity
 *
 **/

#include <config.h>
#include "../utils.h"
#include <lasso/id-ff/identity.h>

#ifdef LASSO_WSF_ENABLED
#include <lasso/id-wsf/identity.h>
#include <lasso/id-wsf-2.0/identity.h>
#endif

#include <lasso/id-ff/identityprivate.h>

struct _LassoIdentityPrivate
{
	gboolean dispose_has_run;
#ifdef LASSO_WSF_ENABLED
	guint last_entry_id;
	GHashTable *resource_offerings_map; /* of LassoDiscoResourceOffering */
	GList *svcMDID; /* of char* */
#endif
};

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_identity_add_federation:
 * @identity: a #LassoIdentity
 * @federation: the #LassoFederation
 *
 * Adds @federation as a known federation for @identity.  @federation is
 * then owned by the identity; caller must not free it.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_identity_add_federation(LassoIdentity *identity, LassoFederation *federation)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_FEDERATION(federation),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* add the federation, replace if one already exists */
	g_hash_table_insert(identity->federations,
			g_strdup(federation->remote_providerID), federation);
	identity->is_dirty = TRUE;

	return 0;
}

/**
 * lasso_identity_get_federation:
 * @identity: a #LassoIdentity
 * @providerID: the provider ID
 *
 * Looks up and returns the #LassoFederation for this provider ID.
 *
 * Return value: the #LassoFederation; or NULL if it didn't exist.  The
 *      #LassoFederation is internally allocated.  It must not be freed,
 *      modified or stored.
 **/
LassoFederation*
lasso_identity_get_federation(LassoIdentity *identity, const char *providerID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);
	g_return_val_if_fail(providerID != NULL, NULL);

	return g_hash_table_lookup(identity->federations, providerID);
}

/**
 * lasso_identity_remove_federation:
 * @identity: a #LassoIdentity
 * @providerID: the provider ID
 *
 * Remove federation between identity and provider with @providerID
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_identity_remove_federation(LassoIdentity *identity, const char *providerID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(providerID != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (g_hash_table_remove(identity->federations, providerID) == FALSE) {
		return LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND;
	}
	identity->is_dirty = TRUE;

	return 0;
}

/**
 * lasso_identity_destroy:
 * @identity: a #LassoIdentity
 *
 * Destroys an identity.
 **/
void
lasso_identity_destroy(LassoIdentity *identity)
{
	if (identity == NULL)
		return;
	lasso_node_destroy(LASSO_NODE(identity));
}

#ifdef LASSO_WSF_ENABLED
/**
 * lasso_identity_add_resource_offering:
 * @identity: a #LassoIdentity object
 * @offering: a #LassoDiscoResourceOffering object to add
 *
 * Add a new offering to the identity object to be retrieved later by
 * lasso_identity_get_offerings() or lasso_identity_get_resource_offering().
 * It also allocate an entryId identifier for the offering, look into
 * offering->entryID to get it after this call.
 *
 * Return value: Always 0, there should not be any error (if memory is not exhausted).
 */
gint
lasso_identity_add_resource_offering(LassoIdentity *identity,
		LassoDiscoResourceOffering *offering)
{
	char entry_id_s[20];

	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_RESOURCE_OFFERING(offering),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	do {
		g_snprintf(entry_id_s, 18, "%d", identity->private_data->last_entry_id);
		identity->private_data->last_entry_id++;
	} while (g_hash_table_lookup(identity->private_data->resource_offerings_map, entry_id_s));
	lasso_assign_string(offering->entryID, entry_id_s);
	g_hash_table_insert(identity->private_data->resource_offerings_map,
		g_strdup(offering->entryID), g_object_ref(offering));
	identity->is_dirty = TRUE;

	return 0;
}

/**
 * lasso_identity_remove_resource_offering:
 * @identity: a #LassoIdentity
 * @entryID: the resource offering entry ID
 *
 * Remove resource offering about identity with @entryID
 *
 * Return value: TRUE on success; FALSE if the offering was not found.
 **/
gboolean
lasso_identity_remove_resource_offering(LassoIdentity *identity, const char *entryID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), FALSE);
	g_return_val_if_fail(entryID != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (g_hash_table_remove(identity->private_data->resource_offerings_map, entryID)) {
		identity->is_dirty = TRUE;
		return TRUE;
	} else {
		return FALSE;
	}
}


/* Context type for the callback add_matching_resource_offering_to_list */
struct HelperStruct {
	GList *list;
	const char *service_type;
};

/*
 * Helper function for lasso_identity_get_offerings, match them with a service
 * type string */
static
void add_matching_resource_offering_to_list(char *name, LassoDiscoResourceOffering *offering,
	struct HelperStruct *ctx) 
{
	if (ctx->service_type == NULL ||
		( offering->ServiceInstance != NULL && 
		offering->ServiceInstance->ServiceType != NULL &&
		strcmp(offering->ServiceInstance->ServiceType, ctx->service_type) == 0)) {
		lasso_list_add(ctx->list, offering);
	}
}

/**
 * lasso_identity_get_offerings:
 * @identity: a #LassoIdentity
 * @service_type: a char* string representing the type of service we are looking for
 *
 * Returns a list of #LassoDiscoResourceOffering associated to this service type.
 *
 * Return value: a newly allocated list of #LassoDiscoResourceOffering
 */
GList*
lasso_identity_get_offerings(LassoIdentity *identity, const char *service_type)
{
	struct HelperStruct ctx = { NULL, service_type };

	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);

	g_hash_table_foreach(identity->private_data->resource_offerings_map, 
		(GHFunc)add_matching_resource_offering_to_list, &ctx);

	return ctx.list;
}

/**
 * lasso_identity_resource_offering:
 * @identity: a #LassoIdentity
 * @entryID: the entryID of the researched #LassoDiscoResourceOffering
 *
 * Lookup a #LassoDiscoResourceOffering corresponding to entryID, entryID is
 * usually allocated by lasso_identity_add_resource_offering() inside
 * offering->entryID.
 *
 * Return value: a #LassoDiscoResourceOffering, your must ref it if you intend
 * to keep it around.
 */
LassoDiscoResourceOffering*
lasso_identity_get_resource_offering(LassoIdentity *identity, const char *entryID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);
	g_return_val_if_fail(entryID != NULL, NULL);

	return g_hash_table_lookup(identity->private_data->resource_offerings_map, entryID);
}

gint
lasso_identity_add_svc_md_id(LassoIdentity *identity, gchar *svcMDID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(svcMDID != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	identity->private_data->svcMDID = g_list_append(
			identity->private_data->svcMDID, g_strdup(svcMDID));
	identity->is_dirty = TRUE;

	return 0;
}

GList*
lasso_identity_get_svc_md_ids(LassoIdentity *identity)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);

	return identity->private_data->svcMDID;
}

#endif


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
add_childnode_from_hashtable(G_GNUC_UNUSED gchar *key, LassoNode *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

#ifdef LASSO_WSF_ENABLED
static void
add_text_childnode_from_list(gchar *value, xmlNode *xmlnode)
{
	xmlNewTextChild(xmlnode, NULL, (xmlChar*)"SvcMDID", (xmlChar*)value);
}
#endif

static xmlNode*
get_xmlNode(LassoNode *node, G_GNUC_UNUSED gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoIdentity *identity = LASSO_IDENTITY(node);
#ifdef LASSO_WSF_ENABLED
	xmlNode *t;
#endif

	xmlnode = xmlNewNode(NULL, (xmlChar*)"Identity");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, (xmlChar*)LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, (xmlChar*)"Version", (xmlChar*)"2");

	/* Federations */
	if (g_hash_table_size(identity->federations))
		g_hash_table_foreach(identity->federations,
				(GHFunc)add_childnode_from_hashtable, xmlnode);
#ifdef LASSO_WSF_ENABLED
	/* Resource Offerings */
	g_hash_table_foreach(identity->private_data->resource_offerings_map, 
			(GHFunc)add_childnode_from_hashtable, xmlnode);

	/* Service Metadatas IDs (svcMDID) */
	if (identity->private_data->svcMDID != NULL) {
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"SvcMDIDs", NULL);
		g_list_foreach(identity->private_data->svcMDID,
				(GFunc)add_text_childnode_from_list, t);
	}
#endif

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdentity *identity = LASSO_IDENTITY(node);
	xmlNode *t;
#ifdef LASSO_WSF_ENABLED
	xmlNode *t2;
	xmlChar *xml_content;
	gchar *content;
#endif

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		/* Federations */
		if (strcmp((char*)t->name, "Federation") == 0) {
			LassoFederation *federation;
			federation = LASSO_FEDERATION(lasso_node_new_from_xmlNode(t));
			g_hash_table_insert(
					identity->federations,
					g_strdup(federation->remote_providerID), federation);
		}

#ifdef LASSO_WSF_ENABLED
		/* Resource Offerings */
		if (strcmp((char*)t->name, "ResourceOffering") == 0) {
			LassoDiscoResourceOffering *offering;
			offering = LASSO_DISCO_RESOURCE_OFFERING(lasso_node_new_from_xmlNode(t));
			g_hash_table_insert(identity->private_data->resource_offerings_map,
				g_strdup(offering->entryID),
				g_object_ref(offering));
		}

		/* Service Metadatas IDs (SvcMDID) */
		if (strcmp((char*)t->name, "SvcMDIDs") == 0) {
			t2 = t->children;
			while (t2) {
				if (t2->type != XML_ELEMENT_NODE) {
					t2 = t2->next;
					continue;
				}
				xml_content = xmlNodeGetContent(t2);
				content = g_strdup((gchar *)xml_content);
				identity->private_data->svcMDID = g_list_append(
					identity->private_data->svcMDID, content);
				xmlFree(xml_content);
				t2 = t2->next;
			}
		}
#endif

		t = t->next;
	}

	return 0;
}


/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoIdentity *identity = LASSO_IDENTITY(object);


	if (identity->private_data->dispose_has_run == FALSE) {
		identity->private_data->dispose_has_run = TRUE;
#ifdef LASSO_WSF_ENABLED
		if (identity->private_data->svcMDID != NULL) {
			g_list_foreach(identity->private_data->svcMDID, (GFunc)g_free, NULL);
			g_list_free(identity->private_data->svcMDID);
			identity->private_data->svcMDID = NULL;
		}
		g_hash_table_destroy(identity->private_data->resource_offerings_map);
#endif

		g_hash_table_destroy(identity->federations);
		identity->federations = NULL;

		G_OBJECT_CLASS(parent_class)->dispose(object);
	}
}

static void
finalize(GObject *object)
{
	LassoIdentity *identity = LASSO_IDENTITY(object);
	g_free(identity->private_data);
	identity->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdentity *identity)
{
	identity->private_data = g_new0(LassoIdentityPrivate, 1);
	identity->private_data->dispose_has_run = FALSE;
#ifdef LASSO_WSF_ENABLED
	identity->private_data->svcMDID = NULL;
	identity->private_data->last_entry_id = 0;
	identity->private_data->resource_offerings_map = g_hash_table_new_full(g_str_hash, 
			g_str_equal, (GDestroyNotify)g_free, (GDestroyNotify)g_object_unref);
#endif
	identity->federations = g_hash_table_new_full(g_str_hash, g_str_equal,
			(GDestroyNotify)g_free,
			(GDestroyNotify)lasso_federation_destroy);
	identity->is_dirty = FALSE;
}

static void
class_init(LassoIdentityClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_identity_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdentityClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdentity),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdentity", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_identity_new:
 *
 * Creates a new #LassoIdentity.
 *
 * Return value: a newly created #LassoIdentity
 **/
LassoIdentity*
lasso_identity_new()
{
	return g_object_new(LASSO_TYPE_IDENTITY, NULL);
}

/**
 * lasso_identity_new_from_dump:
 * @dump: XML server dump
 *
 * Restores the @dump to a new #LassoIdentity.
 *
 * Return value: a newly created #LassoIdentity; or NULL if an error occured
 **/
LassoIdentity*
lasso_identity_new_from_dump(const gchar *dump)
{
	LassoIdentity *identity;
	xmlDoc *doc;
	xmlNode *rootElement;

	if (dump == NULL)
		return NULL;

	doc = xmlParseMemory(dump, strlen(dump));
	if (doc == NULL)
		return NULL;

	rootElement = xmlDocGetRootElement(doc);
	if (strcmp((char*)rootElement->name, "Identity") != 0) {
		xmlFreeDoc(doc);
		return NULL;
	}
	identity = lasso_identity_new();
	init_from_xml(LASSO_NODE(identity), rootElement);
	xmlFreeDoc(doc);

	return identity;
}

/**
 * lasso_identity_dump:
 * @identity: a #LassoIdentity
 *
 * Dumps @identity content to an XML string.
 *
 * Return value: the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_identity_dump(LassoIdentity *identity)
{
	return lasso_node_dump(LASSO_NODE(identity));
}
