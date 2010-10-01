/* $Id: idwsf2_data_service.c 3101 2007-05-30 11:40:10Z dlaniel $
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

#include "./idwsf2_helper.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "../xml/id-wsf-2.0/disco_abstract.h"
#include "../xml/id-wsf-2.0/disco_service_type.h"
#include "../xml/id-wsf-2.0/disco_provider_id.h"
#include "../xml/id-wsf-2.0/sec_token.h"
#include "../xml/id-wsf-2.0/sbf_framework.h"
#include "../xml/misc_text_node.h"
#include "../utils.h"

/**
 * SECTION: idwsf2-helper
 *
 * Methods to help manipulate EPR elements
 */

/**
 * lasso_wsa_endpoint_reference_get_idwsf2_service_type:
 *
 * Return the disco:ServiceType metadata element content
 *
 * Return value: (transfer none): the content of the first disco:ServiceType metadata, or NULL if
 * none is found.
 */
const char*
lasso_wsa_endpoint_reference_get_idwsf2_service_type(const LassoWsAddrEndpointReference *epr)
{
	LassoIdWsf2DiscoServiceType *disco2_service_type;

	if (! LASSO_IS_WSA_ENDPOINT_REFERENCE (epr) || epr->Metadata == NULL)
		return NULL;
	disco2_service_type = lasso_extract_gobject_from_list (LassoIdWsf2DiscoServiceType,
			LASSO_TYPE_IDWSF2_DISCO_SERVICE_TYPE, epr->Metadata->any);
	if (disco2_service_type) {
		return disco2_service_type->content;
	}
	return NULL;
}

/**
 * lasso_wsa_endpoint_reference_get_idwsf2_provider_id
 * @epr: a #LassoWsAddrEndpointReference object
 *
 * Return the provider ID from the the metadata element of the EPR.
 *
 * Return value: an entityID identifier or NULL if none is found, or the element is empty.
 */
const char*
lasso_wsa_endpoint_reference_get_idwsf2_provider_id(const LassoWsAddrEndpointReference *epr)
{
	LassoIdWsf2DiscoProviderID *disco2_provider_id;

	if (! LASSO_IS_WSA_ENDPOINT_REFERENCE (epr) || epr->Metadata == NULL)
		return NULL;

	/* Get the service type from the EPR */
	disco2_provider_id = lasso_extract_gobject_from_list (LassoIdWsf2DiscoProviderID,
			LASSO_TYPE_IDWSF2_DISCO_PROVIDER_ID, epr->Metadata->any);

	if (disco2_provider_id) {
		return disco2_provider_id->content;
	}

	return NULL;
}

/**
 * lasso_wsa_endpoint_reference_get_idwsf2_security_context_for_security_mechanism:
 * @epr: a #LassoWsAddrEndpointReference object
 * @security_mech_predicate: (allow-none): a predicate to test for security mechanism
 * @security_mech_id: (allow-none): a security mechanism identifier
 * @create: allow to create the element if none if found, @security_mech_id is mandatory when create
 * is TRUE.
 *
 * Return value: (transfer none): a #LassoIdWsf2DiscoSecurityContext, or NULL if none was found and
 * created is FALSE.
 */
LassoIdWsf2DiscoSecurityContext*
lasso_wsa_endpoint_reference_get_idwsf2_security_context_for_security_mechanism(
		const LassoWsAddrEndpointReference *epr,
		gboolean (*sech_mech_predicate)(const char *),
		const char *security_mech_id,
		gboolean create)
{
	LassoIdWsf2DiscoSecurityContext *created = NULL;
	LassoMiscTextNode *new_security_mech_id_declaration;

	if (! LASSO_IS_WSA_ENDPOINT_REFERENCE (epr) || epr->Metadata == NULL)
		return NULL;

	lasso_foreach_full_begin(LassoIdWsf2DiscoSecurityContext*, context, it1, epr->Metadata->any);
	if (LASSO_IS_IDWSF2_DISCO_SECURITY_CONTEXT (context)) {
		lasso_foreach_full_begin(char*, textnode, it2, context->SecurityMechID);
			if (lasso_strisequal(textnode,security_mech_id) || sech_mech_predicate(textnode)) {
				return context;
			}
		lasso_foreach_full_end()
	}
	lasso_foreach_full_end();

	if (create && security_mech_id) {
		created = lasso_idwsf2_disco_security_context_new();
		new_security_mech_id_declaration =
			lasso_misc_text_node_new_with_string(security_mech_id);
		new_security_mech_id_declaration->name = "SecurityMechID";
		new_security_mech_id_declaration->ns_href = LASSO_IDWSF2_DISCOVERY_HREF;
		new_security_mech_id_declaration->ns_prefix = LASSO_IDWSF2_DISCOVERY_PREFIX;
		lasso_list_add_new_gobject (created->SecurityMechID,
				new_security_mech_id_declaration);
		lasso_list_add_new_gobject (epr->Metadata->any, created);
	}
	if (create && ! security_mech_id) {
		message(G_LOG_LEVEL_WARNING, "cannot create a LassoIdWsf2DiscoSecurityContext withou a security_mech_id");
	}

	return created;
}

/**
 * lasso_wsa_endpoint_reference_get_token_by_usage:
 * @epr: a #LassoWsAddrEndpointReference object
 * @security_mech_predicate: (allow-none): a predicate to test for security mechanism
 * @security_mech_id: (allow-none): a security mechanism identifier
 * @usage: the usage to make of the token
 *
 * Try to find a token for the given usage and security mechanism, the security can be chosen by
 * name or by a predicate.
 *
 * Return value: a #LassoNode object or a subclass, representing the token.
 */
static LassoNode*
lasso_wsa_endpoint_reference_get_token_by_usage(
		const LassoWsAddrEndpointReference *epr,
		gboolean (*sec_mech_predicate)(const char *),
		const char *security_mech_id, const char* usage)
{
	LassoIdWsf2DiscoSecurityContext *security_context;

	security_context =
		lasso_wsa_endpoint_reference_get_idwsf2_security_context_for_security_mechanism(
			epr, sec_mech_predicate, security_mech_id, TRUE);
	lasso_foreach_full_begin (LassoIdWsf2SecToken*, token, iter, security_context->Token);
	if (LASSO_IS_IDWSF2_SEC_TOKEN (token)) {
		if (usage && lasso_strisequal(token->usage,usage)) {
			if (LASSO_IS_NODE(token->any)) {
				return (LassoNode*)token->any;
			} else if (token->ref) {
				message(G_LOG_LEVEL_WARNING, "sec:Token ref attribute is not supported");
				return NULL;
			}
		}

	}
	lasso_foreach_full_end();

	return NULL;
}

/**
 * lasso_wsa_endpoint_reference_get_security_token:
 * @epr: a #LassoWsAddrEndpointReference object
 * @sech_mech_predicate:(allow-none): a boolean function to select the security mechanism for which
 * we want the security token
 * @security_mech_id:(allow-none): an optional specific security mechanism identifier to select the
 * security token.
 *
 * Return the first security token found in the metadata of the @epr object which qualify with
 * respect to the predicate or the given security mechanism identifier. It is an error to pass both
 * of @sech_mech_predicate and @security_mech_id as NULL.
 *
 * Return value:(transfer none): a #LassoNode object or NULL if the query cannot be satisfied.
 */
LassoNode*
lasso_wsa_endpoint_reference_get_security_token (const LassoWsAddrEndpointReference *epr,
		gboolean (*sech_mech_predicate)(const char *), const char *security_mech_id)
{
	return lasso_wsa_endpoint_reference_get_token_by_usage (epr, sech_mech_predicate,
			security_mech_id, LASSO_IDWSF2_SEC_TOKEN_USAGE_SECURITY_TOKEN);
}

/**
 * lasso_wsa_endpoint_reference_get_target_identity_token:
 * @epr: a #LassoWsAddrEndpointReference object
 * @sech_mech_predicate:(allow-none): a boolean function to select the security mechanism for which
 * we want the security token
 * @security_mech_id:(allow-none): an optional specific security mechanism identifier to select the
 * security token.
 *
 * Return the first target identity token found in the metadata of the @epr object which qualify
 * with respect to the predicate or the given security mechanism identifier. It is an error to pass
 * both of @sech_mech_predicate and @security_mech_id as NULL.
 *
 * Return value:(transfer none): a #LassoNode object or NULL if the query cannot be satisfied.
 */
LassoNode*
lasso_wsa_endpoint_reference_get_target_identity_token(const LassoWsAddrEndpointReference *epr,
		gboolean (*sech_mech_predicate)(const char *), const char *security_mech_id)
{
	return lasso_wsa_endpoint_reference_get_token_by_usage (epr, sech_mech_predicate,
			security_mech_id, LASSO_IDWSF2_SEC_TOKEN_USAGE_TARGET_IDENTITY);
}

/**
 * lasso_wsa_endpoint_reference_new_for_idwsf2_service:
 * @address: the URL of the SOAP endpoint where the service is anchored
 * @service_type: an URI identifying the ID-WSF 2.0 service type
 * @provider_id: an URI identifying the SAML 2.0 service provider hosting the service, this should
 * help in finding key material for security mechanisms.
 * @abstract: a human description of the service.
 *
 * Create and populate a new #LassoWsAddrEndpointReference object.
 *
 * Return value: a newly created #LassoWsAddrEndpointReference.
 */
LassoWsAddrEndpointReference*
lasso_wsa_endpoint_reference_new_for_idwsf2_service(const char *address,
		const char *service_type, const char *provider_id, const char *abstract)
{
	LassoWsAddrEndpointReference *epr = NULL;
	LassoWsAddrMetadata *metadata = NULL;

	/* Check parameters */
	if (address == NULL || service_type == NULL || provider_id == NULL || abstract == NULL)
		return NULL;

	/* Build EndpointReference */
	epr = lasso_wsa_endpoint_reference_new();

	/* Address */
	epr->Address = lasso_wsa_attributed_uri_new_with_string(address);

	/* Metadatas */
	metadata = lasso_wsa_metadata_new();
	epr->Metadata = metadata;

	/* Abstract */
	lasso_list_add_new_gobject(metadata->any,
			lasso_idwsf2_disco_abstract_new_with_string(abstract));

	/* ProviderID */
	lasso_list_add_new_gobject(metadata->any,
			lasso_idwsf2_disco_provider_id_new_with_string(provider_id));

	/* ServiceType */
	lasso_list_add_new_gobject(metadata->any,
			lasso_idwsf2_disco_service_type_new_with_string(service_type));

	/* Framework */
	lasso_list_add_new_gobject(metadata->any,
			lasso_idwsf2_sbf_framework_new_full("2.0"));

	return epr;
}

/**
 * lasso_wsa_endpoint_reference_add_security_token:
 * @epr: a #LassoWsAddrEndpointReference object
 * @security_token: a security token as a #LassoNode object
 * @security_mechanisms:(element-type utf8): a list of security mechanism
 * for whom the token is made
 *
 * Add a new security context declaration for the given security mechanisms identifiers and populate
 * it with a security token.
 *
 * Return value: 0 if successfull, an error code otherwise.
 */
int
lasso_wsa_endpoint_reference_add_security_token(LassoWsAddrEndpointReference *epr,
		LassoNode *security_token, GList *security_mechanisms)
{
	LassoIdWsf2SecToken *sec_token = NULL;
	LassoWsAddrMetadata *metadata = NULL;
	LassoIdWsf2DiscoSecurityContext *security_context = NULL;
	int rc = 0;

	lasso_bad_param(WSA_ENDPOINT_REFERENCE, epr);
	lasso_bad_param(NODE, security_token);

	lasso_extract_node_or_fail(metadata, epr->Metadata, WSA_METADATA, LASSO_PARAM_ERROR_INVALID_VALUE);

	sec_token = lasso_idwsf2_sec_token_new();
	lasso_assign_gobject(sec_token->any, security_token);
	lasso_assign_string(sec_token->usage, LASSO_IDWSF2_SEC_TOKEN_USAGE_SECURITY_TOKEN);

	security_context = lasso_idwsf2_disco_security_context_new();
	lasso_assign_list_of_strings(security_context->SecurityMechID,
			security_mechanisms);
	lasso_list_add_new_gobject(security_context->Token, sec_token);
	lasso_list_add_new_gobject(metadata->any, security_context);
cleanup:
	return rc;
}

static GHashTable *_mapping = NULL;

static GHashTable *_get_mapping() {
	if (_mapping == NULL) {
		_mapping = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify) g_free, NULL);
	}
	return _mapping;
}


/**
 * lasso_wsa_endpoint_reference_associate_service_to_type:
 * @service_type_uri: a service type to associate
 * @g_type: the type of the profile object handling this service type
 *
 * Associate a profile type to a service type.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_wsa_endpoint_reference_associate_service_to_type(
		const char *service_type_uri, GType g_type)
{
	int rc = 0;

	lasso_check_non_empty_string(service_type_uri);
	if (! g_type_is_a(g_type, LASSO_TYPE_IDWSF2_PROFILE)) {
		return LASSO_PARAM_ERROR_INVALID_VALUE;
	}
	g_hash_table_insert(_get_mapping(),
			g_strdup(service_type_uri), (gpointer)g_type);
cleanup:
	return rc;
}

/**
 * lasso_wsa_endpoint_reference_get_service:
 * @epr: a #LassoWsAddrEndpointReference object
 *
 * Get a profile object able to communicate with the service represented by this EPR.
 *
 * Return object: a newly created #LassoIdWsf2Profile instance.
 */
LassoIdWsf2Profile *
lasso_wsa_endpoint_reference_get_service(
		LassoWsAddrEndpointReference *epr)
{
	GType type;
	const char *service_type_uri;

	if (! LASSO_IS_WSA_ENDPOINT_REFERENCE(epr))
		return NULL;

	service_type_uri = lasso_wsa_endpoint_reference_get_idwsf2_service_type(epr);
	type = (GType)g_hash_table_lookup(_get_mapping(), service_type_uri);
	if (type) {
		LassoIdWsf2Profile *profile;

		profile = (LassoIdWsf2Profile*)g_object_new(type, NULL);
		lasso_idwsf2_profile_set_epr(profile, epr);

		return profile;
	}
	return NULL;
}
