/* $Id$
 *
 *
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

#include "id_ff_extensions.h"
#include "../xml/idwsf_strings.h"
#include "id_ff_extensions_private.h"
#include "../xml/disco_description.h"
#include "../xml/disco_resource_offering.h"
#include "../xml/disco_service_instance.h"
#include "../xml/id-wsf-2.0/disco_service_context.h"
#include "../id-ff/profile.h"
#include "../id-ff/server.h"
#include "../id-ff/loginprivate.h"
#include "../id-ff/serverprivate.h"
#include "../id-ff/identityprivate.h"
#include "../xml/saml_attribute.h"
#include "../xml/saml_attribute_value.h"
#include "../xml/saml_attribute_statement.h"
#include "../id-wsf-2.0/server.h"

/**
 * SECTION:id-ff-extensions
 *
 * Those functions are called from ID-FF part of lasso when ID-WSF support is enabled. They enable
 * the boot-straping of the ID-WSF services, notably the access to the Discovery service (see
 * #LassoDiscovery).
 */

/**
 * lasso_login_assertion_add_discovery:
 * @login: a #LassoLogin object
 * @assertion: a #LassoSamlAssertion object
 *
 * Adds AttributeStatement and ResourceOffering attributes to @assertion of a @login object if there
 * is a discovery service registerered in the @LassoLogin.server field.
 * .
 **/
void
lasso_login_assertion_add_discovery(LassoLogin *login, LassoSamlAssertion *assertion)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoDiscoResourceOffering *resourceOffering;
	LassoDiscoServiceInstance *serviceInstance, *newServiceInstance;
	LassoSamlAttributeStatement *attributeStatement;
	LassoSamlAttribute *attribute;
	LassoSamlAttributeValue *attributeValue;

	serviceInstance = lasso_server_get_service(profile->server, LASSO_DISCO_HREF);
	if (LASSO_IS_DISCO_SERVICE_INSTANCE(serviceInstance) &&
			login->private_data->resourceId) {
		newServiceInstance = lasso_disco_service_instance_copy(serviceInstance);

		resourceOffering = lasso_disco_resource_offering_new(newServiceInstance);
		lasso_release_gobject(newServiceInstance);
		lasso_assign_gobject(resourceOffering->ResourceID, login->private_data->resourceId);

		attributeValue = lasso_saml_attribute_value_new();
		lasso_list_add_new_gobject(attributeValue->any, resourceOffering);

		attribute = lasso_saml_attribute_new();
		lasso_assign_string(attribute->attributeName, "DiscoveryResourceOffering");
		lasso_assign_string(attribute->attributeNameSpace, LASSO_DISCO_HREF);
		lasso_list_add_new_gobject(attribute->AttributeValue, attributeValue);

		attributeStatement = lasso_saml_attribute_statement_new();
		lasso_list_add_new_gobject(attributeStatement->Attribute, attribute);

		lasso_assign_new_gobject(assertion->AttributeStatement, attributeStatement);

		/* FIXME: Add CredentialsRef and saml:Advice Assertions */
	}
}


/**
 * lasso_login_set_encryptedResourceId:
 * @login: a #LassoLogin object
 * @encryptedResourceId: the #LassoDiscoEncryptedResourceID to setup in the login object
 *
 * Set the #LassoDiscoEncryptedResourceID to place the next produced assertions as an ID-WSF 1.0
 * bootstrap.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_login_set_encryptedResourceId(LassoLogin *login,
		LassoDiscoEncryptedResourceID *encryptedResourceId)
{
	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_DISCO_ENCRYPTED_RESOURCE_ID(encryptedResourceId),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	lasso_assign_gobject(login->private_data->encryptedResourceId, encryptedResourceId);

	return 0;
}


/**
 * lasso_login_set_resourceId:
 * @login: a #LassoLogin
 * @content: a resourceID identifier
 *
 * Set the resourceId to place in the next produced assertion for ID-WSF bootstrap.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_login_set_resourceId(LassoLogin *login, const char *content)
{
	g_return_val_if_fail(LASSO_IS_LOGIN(login), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(content != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	lasso_assign_new_gobject(login->private_data->resourceId, lasso_disco_resource_id_new(content));
	return 0;
}


/**
 * lasso_server_add_service:
 * @server: a #LassoServer
 * @service: a #LassoNode object implementing representing a service endpoint.
 *
 * Add a service to the registry of service of this #LassoServer object.
 *
 * Return value: 0 on success; a negative value if an error occured.
 **/
gint
lasso_server_add_service(LassoServer *server, LassoNode *service)
{
	g_return_val_if_fail(LASSO_IS_SERVER(server), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(service != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (LASSO_IS_DISCO_SERVICE_INSTANCE(service)) {
		g_hash_table_insert(server->services,
				g_strdup(LASSO_DISCO_SERVICE_INSTANCE(service)->ServiceType),
				g_object_ref(service));
	} else if (LASSO_IS_IDWSF2_DISCO_SVC_METADATA(service)) {
		return lasso_server_add_svc_metadata(server,
				LASSO_IDWSF2_DISCO_SVC_METADATA(service));
	} else {
		return LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ;
	}
	return 0;
}


static void
add_service_childnode(G_GNUC_UNUSED gchar *key, LassoNode *value, xmlNode *xmlnode)
{
	xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(value), TRUE));
}


void
lasso_server_dump_id_wsf_services(LassoServer *server, xmlNode *xmlnode)
{
	if (g_hash_table_size(server->services)) {
		xmlNode *t;
		t = xmlNewTextChild(xmlnode, NULL, (xmlChar*)"Services", NULL);
		g_hash_table_foreach(server->services,
				(GHFunc)add_service_childnode, t);
	}
}


void
lasso_server_init_id_wsf_services(LassoServer *server, xmlNode *t) {
	xmlNode *t2 = t->children;
	/* Services */
	if (strcmp((char*)t->name, "Services") == 0) {
		while (t2) {
			LassoDiscoServiceInstance *s;
			if (t2->type != XML_ELEMENT_NODE) {
				t2 = t2->next;
				continue;
			}
			s = g_object_new(LASSO_TYPE_DISCO_SERVICE_INSTANCE, NULL);
			LASSO_NODE_GET_CLASS(s)->init_from_xml(LASSO_NODE(s), t2);
			g_hash_table_insert(server->services, g_strdup(s->ServiceType), s);
			t2 = t2->next;
		}
	}
}


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
void add_matching_resource_offering_to_list(G_GNUC_UNUSED char *name, LassoDiscoResourceOffering *offering,
	struct HelperStruct *ctx)
{
	if (ctx->service_type == NULL ||
		( offering->ServiceInstance != NULL &&
		offering->ServiceInstance->ServiceType != NULL &&
		strcmp(offering->ServiceInstance->ServiceType, ctx->service_type) == 0)) {
		lasso_list_add_gobject(ctx->list, offering);
	}
}


/**
 * lasso_identity_get_offerings:
 * @identity: a #LassoIdentity
 * @service_type: a char* string representing the type of service we are looking for
 *
 * Returns a list of #LassoDiscoResourceOffering associated to this service type.
 *
 * Return value:(transfer full)(element-type LassoDiscoResourceOffering): a newly allocated list of #LassoDiscoResourceOffering
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
 * Return value:(transfer none)(allow-none): a #LassoDiscoResourceOffering, your must ref it if you intend
 * to keep it around.
 */
LassoDiscoResourceOffering*
lasso_identity_get_resource_offering(LassoIdentity *identity, const char *entryID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);
	g_return_val_if_fail(entryID != NULL, NULL);

	return g_hash_table_lookup(identity->private_data->resource_offerings_map, entryID);
}


/**
 * lasso_server_add_service_from_dump:
 * @server: a #LassoServer
 * @dump: the XML dump of a #LassoNode representing a service endpoint.
 *
 * An utility function that parse a #LassoNode dump an try to add it as a
 * service using lasso_server_add_service.
 *
 * Return value: 0 if succesfull, LASSO_PARAM_ERROR_BAD_TYPE_OF_NULL_OBJECT if
 * said dump is not a #LassoNode or is not of the righ type,
 * LASSO_PARAM_ERROR_INVALID_VALUE if dump is NULL.
 **/
gint
lasso_server_add_service_from_dump(LassoServer *server, const gchar *dump)
{
	LassoNode *node;
	gint return_code;

	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	node = lasso_node_new_from_dump(dump);

	return_code = lasso_server_add_service(server, node);

	g_object_unref(node);

	return return_code;
}


/**
 * lasso_server_get_service:
 * @server: a #LassoServer
 * @serviceType: the service type
 *
 * Look up a disco service instance corresponding to this service type.
 *
 * Return value:(transfer none)(allow-none): the #LassoDiscoServiceInstance, NULL if it was not found.
 *     The #LassoDiscoServiceInstance is owned by Lasso and should not be
 *     freed.
 **/
LassoDiscoServiceInstance*
lasso_server_get_service(LassoServer *server, const gchar *serviceType)
{
	return g_hash_table_lookup(server->services, serviceType);
}
