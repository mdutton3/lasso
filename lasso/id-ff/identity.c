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

#include <lasso/lasso_config.h>
#include <lasso/id-ff/identity.h>

#ifdef LASSO_WSF_ENABLED
#include <lasso/id-wsf/identity.h>
#include <lasso/id-wsf-2.0/identity.h>
#endif

#include <lasso/id-ff/identityprivate.h>

struct _LassoIdentityPrivate
{
	GList *resource_offerings;
	gboolean dispose_has_run;
	GList *svcMD;
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
gint
lasso_identity_add_resource_offering(LassoIdentity *identity,
		LassoDiscoResourceOffering *offering)
{
	/* XXX: add proper entry id to offering */
	int entry_id = 1;
	char entry_id_s[20];
	GList *iter;
	LassoDiscoResourceOffering *t;
	
	g_snprintf(entry_id_s, 18, "%d", entry_id);
	iter = identity->private_data->resource_offerings;
	while (iter) {
		t = iter->data;
		iter = g_list_next(iter);
		if (strcmp(t->entryID, entry_id_s) == 0) {
			entry_id++;
			g_snprintf(entry_id_s, 18, "%d", entry_id);
			iter = identity->private_data->resource_offerings; /* rewind */
		}
	}
		
	offering->entryID = g_strdup(entry_id_s);
	identity->private_data->resource_offerings = g_list_append(
			identity->private_data->resource_offerings, g_object_ref(offering));
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
	GList *iter;
	LassoDiscoResourceOffering *t;
	
	iter = identity->private_data->resource_offerings;
	while (iter) {
		t = iter->data;
		iter = g_list_next(iter);
		if (strcmp(t->entryID, entryID) == 0) {
			identity->private_data->resource_offerings = g_list_remove(
					identity->private_data->resource_offerings, t);
			lasso_node_destroy(LASSO_NODE(t));
			identity->is_dirty = TRUE;
			return TRUE;
		}
	}
	return FALSE;
}


GList*
lasso_identity_get_offerings(LassoIdentity *identity, const char *service_type)
{
	GList *iter;
	LassoDiscoResourceOffering *t;
	GList *result = NULL;
	
	iter = identity->private_data->resource_offerings;
	while (iter) {
		t = iter->data;
		iter = g_list_next(iter);
		if (service_type == NULL || (t->ServiceInstance && strcmp(
					t->ServiceInstance->ServiceType, service_type) == 0)) {
			result = g_list_append(result, g_object_ref(t));
		}
	}

	return result;
}

LassoDiscoResourceOffering* lasso_identity_get_resource_offering(
		LassoIdentity *identity, const char *entryID)
{
	GList *iter;
	LassoDiscoResourceOffering *t;

	iter = identity->private_data->resource_offerings;
	while (iter) {
		t = iter->data;
		iter = g_list_next(iter);
		if (strcmp(t->entryID, entryID) == 0) {
			return t;
		}
	}

	return NULL;
}

gint
lasso_identity_add_svc_md(LassoIdentity *identity, LassoIdWsf2DiscoSvcMetadata *svcMD)
{
	identity->private_data->svcMD = g_list_append(
			identity->private_data->svcMD, g_object_ref(svcMD));
	identity->is_dirty = TRUE;

	return 0;
}

/* GList* */
/* lasso_identity_get_svc_metadatas(LassoIdentity *identity, const char *service_type) */
/* { */
/* 	GList *iter; */
/* 	LassoIdWsf2DiscoSvcMetadata *t; */
/* 	GList *result = NULL; */
/* 	 */
/* 	iter = identity->private_data->svc_metadatas; */
/* 	while (iter) { */
/* 		t = iter->data; */
/* 		iter = g_list_next(iter); */
/* 		if (service_type == NULL || (t->ServiceContext && strcmp( */
/* 					t->ServiceContext->ServiceType, service_type) == 0)) { */
/* 			result = g_list_append(result, g_object_ref(t)); */
/* 		} */
/* 	} */

/* 	return result; */
/* } */


#endif


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
add_childnode_from_hashtable(gchar *key, LassoFederation *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}

#ifdef LASSO_WSF_ENABLED
static void
add_childnode_from_list(LassoNode *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}
#endif

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoIdentity *identity = LASSO_IDENTITY(node);

	xmlnode = xmlNewNode(NULL, (xmlChar*)"Identity");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, (xmlChar*)LASSO_LASSO_HREF, NULL));
	xmlSetProp(xmlnode, (xmlChar*)"Version", (xmlChar*)"2");

	/* Federations */
	if (g_hash_table_size(identity->federations))
		g_hash_table_foreach(identity->federations,
				(GHFunc)add_childnode_from_hashtable, xmlnode);
#ifdef LASSO_WSF_ENABLED
	/* Resource Offerings */
	g_list_foreach(identity->private_data->resource_offerings,
			(GFunc)add_childnode_from_list, xmlnode);

	/* Service Metadatas (SvcMD) */
	if (identity->private_data->svcMD != NULL) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"SvcMDs", NULL);
		g_list_foreach(identity->private_data->svcMD,
				(GFunc)add_childnode_from_list, t);
	}

	/* Simpler version which has the drawback of not working. */
	/* Kept here in case it can work and be a nicer solution */
/* 	g_list_foreach(identity->private_data->svcMD, */
/* 			(GFunc)add_childnode_from_list, xmlnode); */
#endif

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdentity *identity = LASSO_IDENTITY(node);
	xmlNode *t;
	xmlNode *t2;

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
			identity->private_data->resource_offerings = g_list_append(
					identity->private_data->resource_offerings, offering);
		}

		/* Service Metadatas (SvcMD) */
		if (strcmp((char*)t->name, "SvcMDs") == 0) {
			t2 = t->children;
			while (t2) {
				LassoIdWsf2DiscoSvcMetadata *svcMD;
				if (t2->type != XML_ELEMENT_NODE) {
					t2 = t2->next;
					continue;
				}
				svcMD = lasso_idwsf2_disco_svc_metadata_new(NULL, NULL, NULL);
				LASSO_NODE_GET_CLASS(svcMD)->init_from_xml(LASSO_NODE(svcMD), t2);
				identity->private_data->svcMD = g_list_append(
					identity->private_data->svcMD, svcMD);
				t2 = t2->next;
			}
		}

		/* Simpler version which has the drawback of not working. */
		/* Kept here in case it can work and be a nicer solution */
/* 		if (strcmp((char*)t->name, "SvcMD") == 0) { */
/* 			LassoIdWsf2DiscoSvcMetadata *svcMD; */
/* 			svcMD = LASSO_IDWSF2_DISCO_SVC_METADATA(lasso_node_new_from_xmlNode(t)); */
/* 			identity->private_data->svcMD = g_list_append( */
/* 					identity->private_data->svcMD, svcMD); */
/* 		} */
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

	/* FIXME (ID-WSF 1) : Probably necessary, must be tested */
/* 	if (identity->private_data->resource_offerings != NULL) { */
/* 		g_list_free(identity->private_data->resource_offerings); */
/* 		identity->private_data->resource_offerings = NULL; */
/* 	}	 */

	if (identity->private_data->dispose_has_run == TRUE) {
		return;
	}
	identity->private_data->dispose_has_run = TRUE;

	if (identity->private_data->svcMD != NULL) {
		g_list_free(identity->private_data->svcMD);
		identity->private_data->svcMD = NULL;
	}

	g_hash_table_destroy(identity->federations);
	identity->federations = NULL;

	G_OBJECT_CLASS(parent_class)->dispose(object);
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
	identity->private_data->resource_offerings = NULL;
	identity->private_data->dispose_has_run = FALSE;
	identity->private_data->svcMD = NULL;

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
	if (g_hash_table_size(identity->federations) == 0)
		return g_strdup("");

	return lasso_node_dump(LASSO_NODE(identity));
}
