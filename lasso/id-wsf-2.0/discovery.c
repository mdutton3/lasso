/* $Id: discovery.c,v 1.75 2007/01/03 23:35:17 Exp $
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
 * SECTION:idwsf2_discovery
 * @short_description: ID-WSF 2.0 Discovery Service profile
 *
 * The Discovery service usually runs on the principal identity provider and
 * knowns about resources and services related to the principal.  Attribute
 * providers can register themselves as offering resources for an user while
 * other services can ask where to find a given resource.
 */

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>

#include "../saml-2.0/saml2_helper.h"

#include "../xml/saml_attribute_value.h"
#include "../xml/xml_enc.h"

#include "../xml/soap-1.1/soap_fault.h"

#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/samlp2_name_id_policy.h"

#include "../xml/id-wsf-2.0/disco_query.h"
#include "../xml/id-wsf-2.0/disco_query_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_query.h"
#include "../xml/id-wsf-2.0/disco_svc_md_query_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_register.h"
#include "../xml/id-wsf-2.0/disco_svc_md_register_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_replace.h"
#include "../xml/id-wsf-2.0/disco_svc_md_replace_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_delete.h"
#include "../xml/id-wsf-2.0/disco_svc_md_delete_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_association_query.h"
#include "../xml/id-wsf-2.0/disco_svc_md_association_query_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_association_add.h"
#include "../xml/id-wsf-2.0/disco_svc_md_association_add_response.h"
#include "../xml/id-wsf-2.0/disco_svc_md_association_delete.h"
#include "../xml/id-wsf-2.0/disco_svc_md_association_delete_response.h"
#include "../xml/id-wsf-2.0/disco_requested_service.h"
#include "../xml/id-wsf-2.0/disco_abstract.h"
#include "../xml/id-wsf-2.0/disco_provider_id.h"
#include "../xml/id-wsf-2.0/disco_service_type.h"
#include "../xml/id-wsf-2.0/disco_security_context.h"
#include "../xml/id-wsf-2.0/disco_service_context.h"
#include "../xml/id-wsf-2.0/disco_endpoint_context.h"
#include "../xml/id-wsf-2.0/disco_options.h"
#include "../xml/id-wsf-2.0/sec_token.h"
#include "../xml/id-wsf-2.0/util_status.h"
#include "../xml/id-wsf-2.0/sbf_framework.h"

#include "../xml/ws/wsa_endpoint_reference.h"

#include "../id-ff/server.h"
#include "../id-ff/provider.h"
#include "../id-ff/providerprivate.h"

#include "./discovery.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "./soap_binding.h"
#include "./idwsf2_helper.h"
#include "./saml2_login.h"
#include "../utils.h"

struct _LassoIdWsf2DiscoveryPrivate
{
	gboolean dispose_has_run;
	GList *metadatas; /* of LassoIdWsf2DiscoSvcMetadata* */
	GList *requested_services; /* of LassoIdWsf2DiscoRequestedService */
	GList *svcmdids; /* of utf8 */
};

#define LASSO_IDWSF2_DISCOVERY_ELEMENT_METADATAS "Metadatas"
#define LASSO_IDWSF2_DISCOVERY_ELEMENT_REQUESTED_SERVICES "RequestedServices"
#define LASSO_IDWSF2_DISCOVERY_ELEMENT_REQUESTED_SERVICES "RequestedServices"


static int
lasso_idwsf2_discovery_add_identity_to_epr(LassoIdWsf2Discovery *discovery,
		LassoWsAddrEndpointReference *epr,
		const char *provider_id,
		const char *security_mechanism)
{
	LassoIdentity *identity = discovery->parent.parent.identity;
	LassoFederation *federation = NULL;
	LassoSaml2Assertion *assertion;
	LassoProvider *provider = NULL;
	GList security_mechanisms = { .data = (char*)security_mechanism, .next = NULL, .prev = NULL };

	if (! LASSO_IS_IDENTITY(identity))
		return LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND;

	federation = lasso_identity_get_federation(identity, provider_id);
	if (federation == NULL || ! LASSO_IS_SAML2_NAME_ID(federation->local_nameIdentifier))
		return LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND;
	provider = lasso_server_get_provider(discovery->parent.parent.server, provider_id);
	if (! provider) {
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
	}

	assertion =
		lasso_server_create_assertion_as_idwsf2_security_token(discovery->parent.parent.server,
				LASSO_SAML2_NAME_ID(federation->local_nameIdentifier),
				LASSO_DURATION_HOUR, 2 * LASSO_DURATION_DAY, provider ? TRUE :
				FALSE, provider);

	if (assertion == NULL ) {
		return LASSO_ERROR_UNDEFINED;
	}

	return lasso_wsa_endpoint_reference_add_security_token(epr,
			(LassoNode*)assertion, &security_mechanisms);
}



static LassoWsAddrEndpointReference*
lasso_idwsf2_discovery_build_epr(LassoIdWsf2Discovery *discovery,
	LassoIdWsf2DiscoSvcMetadata *svc_metadata,
	LassoIdWsf2DiscoServiceContext *service_context,
	LassoIdWsf2DiscoEndpointContext *endpoint_context)
{
	LassoIdentity *identity;
	LassoWsAddrEndpointReference *epr = NULL;
	LassoWsAddrMetadata *metadata = NULL;
	LassoIdWsf2DiscoAbstract *abstract;
	LassoIdWsf2DiscoProviderID *provider_id;
	LassoIdWsf2DiscoServiceType *service_type;
	LassoProvider *provider = NULL;
	GList *i;


	if (LASSO_IS_IDENTITY(discovery->parent.parent.identity)) {
		identity = discovery->parent.parent.identity;
	}
	epr = lasso_wsa_endpoint_reference_new();
	epr->Address = lasso_wsa_attributed_uri_new_with_string(
		(gchar*)endpoint_context->Address->data);
	metadata = lasso_wsa_metadata_new();
	epr->Metadata = metadata;
	/* Abstract */
	if (svc_metadata->Abstract) {
		abstract = lasso_idwsf2_disco_abstract_new_with_string(svc_metadata->Abstract);
		lasso_list_add_new_gobject(metadata->any, abstract);
	}
	/* ProviderID */
	if (svc_metadata->ProviderID) {
		provider_id = lasso_idwsf2_disco_provider_id_new_with_string(svc_metadata->ProviderID);
		provider = lasso_server_get_provider(discovery->parent.parent.server, svc_metadata->ProviderID);
		lasso_list_add_new_gobject(metadata->any, provider_id);
	}
	/* ServiceType */
	lasso_foreach(i, service_context->ServiceType)
	{
		service_type = lasso_idwsf2_disco_service_type_new_with_string(i->data);
		lasso_list_add_new_gobject(metadata->any, service_type);
	}
	/* Framework */
	lasso_foreach(i, endpoint_context->Framework)
	{
		lasso_list_add_gobject(metadata->any, i->data);
	}
	/* Identity token */
	lasso_foreach(i, endpoint_context->SecurityMechID)
	{
		int rc = lasso_idwsf2_discovery_add_identity_to_epr(discovery,
				epr,
				svc_metadata->ProviderID,
				(char*)i->data);
		if (rc != 0) {
			message(G_LOG_LEVEL_WARNING,
				"%s cannot add identity token to epr: %s", __func__, lasso_strerror(rc));
			lasso_release_gobject(epr);
			return NULL;
		}
	}
	return epr;
}

static gint
lasso_idwsf2_discovery_status2rc(LassoIdWsf2UtilStatus *status)
{
	size_t i = 0;
	static struct {
		const char *code;
		int rc;
	} code2rc[] = {
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_OK, 0},
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_FAILED, LASSO_IDWSF2_DISCOVERY_ERROR_FAILED },
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_FORBIDDEN, LASSO_IDWSF2_DISCOVERY_ERROR_FORBIDDEN },
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_DUPLICATE, LASSO_IDWSF2_DISCOVERY_ERROR_DUPLICATE },
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_LOGICAL_DUPLICATE,
			LASSO_IDWSF2_DISCOVERY_ERROR_LOGICAL_DUPLICATE },
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NO_RESULTS, LASSO_IDWSF2_DISCOVERY_ERROR_NO_RESULTS },
		{ LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NOT_FOUND, LASSO_IDWSF2_DISCOVERY_ERROR_NOT_FOUND }
	};
	int rc = LASSO_WSF_PROFILE_ERROR_UNKNOWN_STATUS_CODE;

	if (! LASSO_IS_IDWSF2_UTIL_STATUS(status) || ! status->code)
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;

	for (i = 0; i < G_N_ELEMENTS(code2rc); ++i) {
		if (lasso_strisequal(status->code,code2rc[i].code)) {
			rc = code2rc[i].rc;
		}
	}
	/* check second level if necessary */
	if (status->Status && rc == LASSO_IDWSF2_DISCOVERY_ERROR_FAILED) {
		int rc2 = lasso_idwsf2_discovery_status2rc(status->Status->data);
		if (rc2 != LASSO_WSF_PROFILE_ERROR_UNKNOWN_STATUS_CODE &&
				rc2 != LASSO_PROFILE_ERROR_MISSING_STATUS_CODE)
			rc = rc2;
	}
	return rc;
}

#define declare_init_request(name, request_element_type, constructor) \
gint \
lasso_idwsf2_discovery_init_##name(LassoIdWsf2Discovery *discovery) \
{ \
	LassoIdWsf2Profile *idwsf2_profile = NULL; \
	LassoProfile *profile = NULL; \
	request_element_type *request_element = NULL; \
	LassoSoapEnvelope *envelope = NULL; \
	int rc = 0; \
 \
	lasso_bad_param(IDWSF2_DISCOVERY, discovery); \
 \
	lasso_release_list_of_gobjects(discovery->private_data->metadatas) \
	lasso_release_list_of_gobjects(discovery->private_data->requested_services) \
	idwsf2_profile = &discovery->parent; \
	profile = &idwsf2_profile->parent; \
	lasso_check_good_rc(lasso_idwsf2_profile_init_request(idwsf2_profile)); \
	request_element = constructor(); \
	envelope = lasso_idwsf2_profile_get_soap_envelope_request(idwsf2_profile); \
	lasso_assign_new_gobject(profile->request, request_element); \
	lasso_soap_envelope_add_to_body(envelope, (LassoNode*)request_element); \
 \
cleanup: \
	return rc; \
}

/* Metadata requests */

/**
 * lasso_idwsf2_discovery_init_query
 * @discovery: a #LassoIdWsf2Discovery
 *
 * Initialise a request for ID-WSF discovery Query to a discovery service.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
declare_init_request(query, LassoIdWsf2DiscoQuery, lasso_idwsf2_disco_query_new)

/**
 * lasso_idwsf2_discovery_init_metadata_register:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Initialise a ID-WSF service metadata registration request to a Discovery service.
 *
 * Return value: 0 on success; an error code otherwise.
 **/
declare_init_request(metadata_register, LassoIdWsf2DiscoSvcMDRegister,
		lasso_idwsf2_disco_svc_md_register_new);

/**
 * lasso_idwsf2_discovery_init_metadata_replace:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Initialise a ID-WSF service metadata replace request to a Discovery service.
 *
 * Return value: 0 on success; an error code otherwise.
 **/
declare_init_request(metadata_replace, LassoIdWsf2DiscoSvcMDReplace,
		lasso_idwsf2_disco_svc_md_replace_new);

/**
 * lasso_idwsf2_discovery_init_metadata_query:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Initialise a ID-WSF service metadata query request to a Discovery service
 *
 * Return value: 0 on success; an error code otherwise.
 **/
declare_init_request(metadata_query, LassoIdWsf2DiscoSvcMDQuery,
		lasso_idwsf2_disco_svc_md_query_new);

/**
 * lasso_idwsf2_discovery_init_metadata_delete:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Initialise a ID-WSF service metadata query request to a Discovery service
 *
 * Return value: 0 on success; an error code otherwise.
 **/
declare_init_request(metadata_delete, LassoIdWsf2DiscoSvcMDDelete,
		lasso_idwsf2_disco_svc_md_delete_new);

/**
 * lasso_idwsf2_discovery_init_metadata_association_add:
 * @discovery: a #LassoIdWsf2Discovery
 * @svcMDID: identifier of the service metadata the user wants to associate with
 *
 * Initialise a request to associate a user account to a service metadata, allowing
 * a WSC to request this service for data related to this user account.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
declare_init_request(metadata_association_add, LassoIdWsf2DiscoSvcMDAssociationAdd,
		lasso_idwsf2_disco_svc_md_association_add_new)

declare_init_request(metadata_association_delete, LassoIdWsf2DiscoSvcMDAssociationDelete,
		lasso_idwsf2_disco_svc_md_association_delete_new)
declare_init_request(metadata_association_query, LassoIdWsf2DiscoSvcMDAssociationQuery,
		lasso_idwsf2_disco_svc_md_association_query_new)


/**
 * lasso_idwsf2_discovery_add_service_metadata:
 * @idwsf2_discovery: a #LassoIdWsf2Discovery object
 * @service_metadata: a #LassoIdWsf2DiscoSvcMetadata object to add to the register request.
 *
 * Add a new metadata object to a request.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_idwsf2_discovery_add_service_metadata(LassoIdWsf2Discovery *discovery,
		LassoIdWsf2DiscoSvcMetadata *service_metadata)
{
	lasso_bad_param(IDWSF2_DISCOVERY, discovery);
	lasso_bad_param(IDWSF2_DISCO_SVC_METADATA, service_metadata);
	lasso_list_add_gobject(discovery->private_data->metadatas,
			service_metadata);
	return 0;
}

/**
 * lasso_idwsf2_discovery_add_simple_service_metadata:
 * @idwsf2_discovery: a #LassoIdWsf2Discovery object
 * @abstract:(allow-none): a human description of the service
 * @provider_id:(allow-none): the provider id of the service to register, if none is given,
 * providerId of the current #LassoServer object is used
 * @service_types:(element-type utf8)(allow-none): an array of service type URIs
 * @options:(element-type LassoIdWsf2DiscoOptions)(allow-none): an array of option string
 * @address:(allow-none): the URI of the service endpoint for the default EndpointContext
 * @security_mechanisms:(allow-none)(element-type utf8): the security mechanisms supported by the
 * service
 *
 * Add new metadata to the current Metadata Register request.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_idwsf2_discovery_add_simple_service_metadata(LassoIdWsf2Discovery *idwsf2_discovery,
		const char *abstract, const char *provider_id, GList *service_types, GList *options,
		const char *address, GList *security_mechanisms)
{
	LassoIdWsf2DiscoSvcMetadata *service_metadata;
	LassoIdWsf2DiscoServiceContext *service_context;
	LassoIdWsf2DiscoEndpointContext *endpoint_context;
	int rc = 0;

	lasso_bad_param(IDWSF2_DISCOVERY, idwsf2_discovery);
	lasso_check_non_empty_string(address);
	service_metadata = lasso_idwsf2_disco_svc_metadata_new();
	if (abstract) {
		lasso_assign_string(service_metadata->Abstract, abstract);
	}
	if (provider_id) {
		lasso_assign_string(service_metadata->ProviderID, provider_id);
	}
	service_context = lasso_idwsf2_disco_service_context_new();
	if (service_types) {
		lasso_assign_list_of_strings(service_context->ServiceType, service_types);
	}
	if (options) {
		lasso_assign_list_of_strings(service_context->Options, options);
	}
	endpoint_context = lasso_idwsf2_disco_endpoint_context_new();
	if (address) {
		lasso_list_add_string(endpoint_context->Address, address);
	}
	lasso_list_add_new_gobject(endpoint_context->Framework,
			lasso_idwsf2_sbf_framework_new_full("2.0"));
	if (security_mechanisms) {
		lasso_assign_list_of_strings(endpoint_context->SecurityMechID, security_mechanisms);
	}

	lasso_list_add_new_gobject(service_context->EndpointContext, endpoint_context);
	lasso_list_add_new_gobject(service_metadata->ServiceContext, service_context);

	rc = lasso_idwsf2_discovery_add_service_metadata(idwsf2_discovery, service_metadata);
	lasso_release_gobject(service_metadata);
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_discovery_get_metadatas:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Return the current list of metadatas in the @discovery object. They can be metadatas just
 * received through a #LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER request or added through
 * lasso_idwsf2_discovery_add_service_metadata() or
 * lasso_idwsf2_discovery_add_simple_service_metadata().
 *
 * Return value:(transfer none)(element-type LassoIdWsf2DiscoSvcMetadata): the list of metadatas.
 */
GList*
lasso_idwsf2_discovery_get_metadatas(LassoIdWsf2Discovery *discovery)
{
	if (! LASSO_IS_IDWSF2_DISCOVERY(discovery) || ! discovery->private_data)
		return NULL;
	return discovery->private_data->metadatas;
}

/**
 * lasso_idwsf2_discovery_get_endpoint_references:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Return the list of wsa:EndpointReference returned by the last discovery query.
 *
 * Return value:(transfer none)(element-type LassoWsAddrEndpointReference): a #GList of
 * LassoWsAddrEndpointReference objects, or NULL if none is found.
 */
GList*
lasso_idwsf2_discovery_get_endpoint_references(LassoIdWsf2Discovery *discovery)
{
	LassoProfile *profile;
	LassoIdWsf2DiscoQueryResponse *response;
	GList *rc = NULL;

	g_return_val_if_fail (LASSO_IS_IDWSF2_DISCOVERY (discovery), NULL);
	profile = &discovery->parent.parent;

	lasso_extract_node_or_fail (response, profile->response, IDWSF2_DISCO_QUERY_RESPONSE, NULL);
	rc = response->EndpointReference;
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_discovery_get_svcmdids:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Return the list of SvcMDID, or service metadata ids, returned by the last discovery query.
 *
 * Return value:(transfer none)(element-type utf8)(allow-none): a list of SvcMDID's.
 */
GList*
lasso_idwsf2_discovery_get_svcmdids(LassoIdWsf2Discovery *discovery)
{
	if (! LASSO_IS_IDWSF2_DISCOVERY(discovery) || ! discovery->private_data)
		return NULL;
	return discovery->private_data->svcmdids;
}

/**
 * lasso_idwsf2_discovery_set_svcmdids:
 * @discovery: a #LassoIdWsf2Discovery object
 * @svcmdids:(element-type utf8)(allow-none): a list of service metadata IDs
 *
 * Set the list of SvcMDID, or service metadata ids.
 *
 */
void
lasso_idwsf2_discovery_set_svcmdids(LassoIdWsf2Discovery *discovery, GList *svcmdids)
{
	if (! LASSO_IS_IDWSF2_DISCOVERY(discovery) || ! discovery->private_data)
		return;
	lasso_assign_list_of_strings(discovery->private_data->svcmdids, svcmdids);
}

/**
 * lasso_idwsf2_discovery_build_request_msg:
 * @discovery: a #LassoIdWsf2Discovery object
 * @security_mechanism:(allow-none):the security mech id to use, if NULL a Bearer mechanism is used.
 *
 * Build the request message using a security mechanism to authenticate the requester and the target
 * identity. If none is given Bearer mechanism is used.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_discovery_build_request_msg(LassoIdWsf2Discovery *discovery,
		const char *security_mechanism)
{
	GList *content = NULL;
	LassoIdWsf2DiscoQuery *query = NULL;
	GList **svc_md_ids = NULL;
	GList **metadatas = NULL;
	gboolean check_svcMDID = FALSE;
	int rc = 0;

	lasso_bad_param(IDWSF2_DISCOVERY, discovery);
	content =
		lasso_soap_envelope_get_body_content(
				lasso_idwsf2_profile_get_soap_envelope_request(
					&discovery->parent));
	switch (lasso_idwsf2_discovery_get_request_type(discovery)) {
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY:
			query = (LassoIdWsf2DiscoQuery*)lasso_list_get_first_child(content);
			lasso_assign_list_of_gobjects(query->RequestedService,
					discovery->private_data->requested_services);

			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER:
			metadatas = &((LassoIdWsf2DiscoSvcMDRegister*)lasso_list_get_first_child(content))->SvcMD;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDQuery*)
					lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REPLACE:
			check_svcMDID = TRUE;
			metadatas = &((LassoIdWsf2DiscoSvcMDReplace*)
					lasso_list_get_first_child(content))->SvcMD;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDDelete*)
					lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDAssociationAdd*)
						lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDAssociationDelete*)
						lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDAssociationQuery*)
						lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_UNKNOWN:
		default:
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_REQUEST);
			break;
	}
	if (metadatas) {
		if (! check_svcMDID) {
			lasso_assign_list_of_gobjects(*metadatas, discovery->private_data->metadatas);
		} else {
			GList *i;
			lasso_foreach(i, discovery->private_data->metadatas) {
				LassoIdWsf2DiscoSvcMetadata *metadata = (LassoIdWsf2DiscoSvcMetadata *)i->data;
				if (lasso_strisempty(metadata->svcMDID)) {
					message(G_LOG_LEVEL_WARNING, "disco:MetadataReplace method called with " \
							"non registered metadatas " \
							"(svcMDID attribute is missing)");
				} else {
					lasso_list_add_gobject(*metadatas, metadata);
				}
			}
		}
	}
	if (svc_md_ids) {
		lasso_assign_list_of_strings(*svc_md_ids, discovery->private_data->svcmdids);
	}
	rc = lasso_idwsf2_profile_build_request_msg(&discovery->parent, security_mechanism);
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_discovery_process_request_msg:
 * @discovery: a #LassoIdWsf2Discovery object
 * @message: a received SOAP message
 *
 * Parse a Discovery service request.
 *
 * Return value: 0 if sucessful, an error code otherwise among:
 * <itemizedlist>
 * <listitem><para>LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if @profile is not a #LassoIdWsf2Profile
 * object,</para></listitem>
 * <listitem><para>LASSO_PARAM_ERROR_INVALID_VALUE if message is NULL,</para></listitem>
 * <listitem><para>LASSO_PROFILE_ERROR_INVALID_MSG if we cannot parse the message,</para></listitem>
 * <listitem><para>LASSO_SOAP_ERROR_MISSING_BODY if the message has no body
 * content.</para></listitem>
 * </itemizedlist>
 */
int
lasso_idwsf2_discovery_process_request_msg(LassoIdWsf2Discovery *discovery, const char *message)
{
	LassoProfile *profile;
	LassoIdWsf2Profile *idwsf2_profile;
	GList *content;
	GList **svc_md_ids = NULL, **metadatas = NULL, **service_types = NULL;
	int rc = 0;

	lasso_bad_param(IDWSF2_DISCOVERY, discovery);
	idwsf2_profile = &discovery->parent;
	profile = &idwsf2_profile->parent;

	lasso_check_good_rc(lasso_idwsf2_profile_process_request_msg(idwsf2_profile, message));

	content =
		lasso_soap_envelope_get_body_content(
				lasso_idwsf2_profile_get_soap_envelope_request(
					&discovery->parent));
	switch (lasso_idwsf2_discovery_get_request_type(discovery)) {
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER:
			metadatas = &((LassoIdWsf2DiscoSvcMDRegister*)
					lasso_list_get_first_child(content))->SvcMD;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY:
			service_types = &((LassoIdWsf2DiscoQuery*)
					lasso_list_get_first_child(content))->RequestedService;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDQuery*)
					lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDDelete*)
					lasso_list_get_first_child(content))->SvcMDID;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDAssociationAdd*)
						lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDAssociationDelete*)
						lasso_list_get_first_child(content))->SvcMDID;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY:
			svc_md_ids = &((LassoIdWsf2DiscoSvcMDAssociationQuery*)
						lasso_list_get_first_child(content))->SvcMDID;
			break;
		default:
				lasso_check_good_rc(
						lasso_idwsf2_profile_init_soap_fault_response(
							idwsf2_profile,
							LASSO_SOAP_FAULT_CODE_CLIENT,
							"Unknown Request Type", NULL));
				rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
			break;
	}
	if (discovery->private_data && svc_md_ids) {
		lasso_assign_list_of_strings(discovery->private_data->svcmdids, *svc_md_ids);
	}
	if (metadatas) {
		lasso_assign_list_of_gobjects(discovery->private_data->metadatas, *metadatas);
	}
	if (service_types) {
		lasso_assign_list_of_gobjects(discovery->private_data->requested_services, *service_types);
	}

cleanup:
	return rc;
}


/**
 * lasso_idwsf2_discovery_get_request_type:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Return the type of the last parsed request.
 *
 * Return value: the type of the last parsed request.
 */
LassoIdWsf2DiscoveryRequestType
lasso_idwsf2_discovery_get_request_type(LassoIdWsf2Discovery *discovery)
{
	if (LASSO_IS_IDWSF2_DISCOVERY(discovery))
	{
		GType request_type = 0;

		request_type = G_TYPE_FROM_INSTANCE(discovery->parent.parent.request);

#define check_request_type(a, b) \
		if (request_type == a) { \
			return b ;\
		}

		check_request_type(LASSO_TYPE_IDWSF2_DISCO_QUERY,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_QUERY,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REGISTER,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_REPLACE,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REPLACE);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_DELETE,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_DELETE,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE);
		check_request_type(LASSO_TYPE_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY,
				LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY);
	}
#undef check_request_type
	return LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_UNKNOWN;

}

/**
 * lasso_idwsf2_discovery_fail_request:
 * @discovery: a #LassoIdWsf2Discovery
 * @status_code: a status code string
 * @status_code2:(allow-none): a second-level status code
 *
 * Fail the last request with the given status code.
 *
 * Return value: 0 on success; or a negative value otherwise.
 */
gint
lasso_idwsf2_discovery_fail_request(LassoIdWsf2Discovery *discovery, const char *status_code,
		const char *status_code2)
{
	LassoIdWsf2DiscoSvcMDAssociationAddResponse *md_association_add_response;
	LassoIdWsf2DiscoSvcMDAssociationDeleteResponse *md_association_delete_response;
	LassoIdWsf2DiscoSvcMDAssociationQueryResponse *md_association_query_response;
	LassoIdWsf2DiscoSvcMDRegisterResponse *md_register_response;
	LassoIdWsf2DiscoSvcMDQueryResponse *md_query_response;
	LassoIdWsf2DiscoSvcMDDeleteResponse *md_delete_response;
	LassoIdWsf2DiscoSvcMDReplaceResponse *md_replace_response;
	LassoIdWsf2DiscoQueryResponse *query_response;
	int rc = 0;
	LassoIdWsf2UtilStatus **status = NULL;
	LassoNode *response = NULL;

	lasso_bad_param(IDWSF2_DISCOVERY, discovery);

	lasso_check_good_rc(lasso_idwsf2_profile_init_response(&discovery->parent));
	switch (lasso_idwsf2_discovery_get_request_type(discovery)) {
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY:
			query_response = lasso_idwsf2_disco_query_response_new();
			response = (LassoNode*)query_response;
			status = &query_response->Status;
			break;

		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER:
			md_register_response = lasso_idwsf2_disco_svc_md_register_response_new();
			response = (LassoNode*)md_register_response;
			status = &md_register_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY:
			md_query_response = lasso_idwsf2_disco_svc_md_query_response_new();
			response = (LassoNode*)md_query_response;
			status = &md_query_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REPLACE:
			md_replace_response = lasso_idwsf2_disco_svc_md_replace_response_new();
			response = (LassoNode*)md_replace_response;
			status = &md_replace_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE:
			md_delete_response = lasso_idwsf2_disco_svc_md_delete_response_new();
			response = (LassoNode*)md_delete_response;
			status = &md_delete_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD:
			md_association_add_response =
				lasso_idwsf2_disco_svc_md_association_add_response_new();
			response = (LassoNode*)md_association_add_response;
			status = &md_association_add_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE:
			md_association_delete_response =
				lasso_idwsf2_disco_svc_md_association_delete_response_new();
			response = (LassoNode*)md_association_delete_response;
			status = &md_association_delete_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY:
			md_association_query_response =
				lasso_idwsf2_disco_svc_md_association_query_response_new();
			response = (LassoNode*)md_association_query_response;
			status = &md_association_query_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_UNKNOWN:
		default:
			response = (LassoNode*)lasso_soap_fault_new_full(
					LASSO_SOAP_FAULT_CODE_CLIENT, "Invalid request");
			break;
	}
	if (response) {
		LassoSoapEnvelope *envelope =
			lasso_idwsf2_profile_get_soap_envelope_response(&discovery->parent);
		lasso_assign_new_gobject(discovery->parent.parent.response, response);
		lasso_soap_envelope_add_to_body(envelope, response);
	}
	if (status) {
		lasso_assign_new_gobject(*status,
				lasso_idwsf2_util_status_new_with_code(status_code, status_code2));
	}

cleanup:
	return rc;
}

static gboolean
_string_list_intersect(GList *a, GList *b)
{
	GList *i, *j;

	if (a == NULL) {
		return TRUE;
	}
	lasso_foreach(i, a)
	{
		lasso_foreach(j, b)
			if (lasso_strisequal(i->data,j->data)) {
				return TRUE;
			}
	}
	return FALSE;
}

static gboolean
_string_list_contains(GList *a, const char *str)
{
	GList *i;

	if (a == NULL)
		return TRUE;
	lasso_foreach(i, a)
		if (lasso_strisequal(i->data,str)) {
			return TRUE;
		}
	return FALSE;
}

static gboolean
_string_list_contains_list(GList *a, GList *b)
{
	GList *i;
	/* empty = all */
	if (a == NULL)
		return TRUE;
	lasso_foreach(i, b)
		if (! _string_list_contains(a, i->data))
			return FALSE;
	return TRUE;
}

void
lasso_idwsf2_discovery_match_request_service_and_metadata2(
		LassoIdWsf2Discovery *discovery,
		LassoIdWsf2DiscoRequestedService *requested_service,
		LassoIdWsf2DiscoSvcMetadata *metadata,
		LassoIdWsf2DiscoServiceContext *service_context,
		LassoIdWsf2DiscoEndpointContext *endpoint_context,
		GList **eprs)
{
	GList *i;
	gboolean result = TRUE;
	gboolean option_result = TRUE;
	LassoIdWsf2DiscoOptions *options = NULL;
	GList *service_options = NULL;


	result = result &&
		_string_list_intersect(requested_service->ServiceType, service_context->ServiceType);
	if (result) {
		result = result && _string_list_contains(requested_service->ProviderID, metadata->ProviderID);
	}
	/* Accumulate options */
	if (result) {
		lasso_foreach(i, service_context->Options)
		{
			options = (LassoIdWsf2DiscoOptions*)i->data;
			service_options = g_list_concat(service_options,
					g_list_copy(options->Option));
		}
		lasso_foreach(i, requested_service->Options)
		{
			option_result = FALSE;
			if (_string_list_contains_list(service_options,
						((LassoIdWsf2DiscoOptions*)i->data)->Option))
			{
				option_result = TRUE;
				break;
			}
		}
		lasso_release_list(service_options);
		result = result && option_result;
	}
	if (result) {
		result = result &&
			_string_list_intersect(requested_service->SecurityMechID, endpoint_context->SecurityMechID);
	}
	if (result) {
		if (requested_service->Framework) {
			result = result &&
				_string_list_intersect(requested_service->Framework, endpoint_context->Framework);
		} else {
			/* FIXME: should be the value of the query SOAP header sbf:Framework */
			GList *k;
			gboolean has20 = FALSE;
			lasso_foreach (k, endpoint_context->Framework) {
				LassoIdWsf2SbfFramework *framework = k->data;
				if (LASSO_IS_IDWSF2_SBF_FRAMEWORK(framework) && lasso_strisequal(framework->version,"2.0"))
					has20 = TRUE;
			}
			result = result && has20;
		}
	}
	if (result) {
		result = result && _string_list_intersect(endpoint_context->Action, requested_service->Action);
	}

	if (result) {
		lasso_list_add_new_gobject(*eprs,
				lasso_idwsf2_discovery_build_epr(
					discovery,
					metadata,
					service_context,
					endpoint_context));
	}

}

void
lasso_idwsf2_discovery_match_request_service_and_metadata(
		LassoIdWsf2Discovery *discovery,
		LassoIdWsf2DiscoRequestedService *requested_service,
		LassoIdWsf2DiscoSvcMetadata *metadata,
		GList **eprs)
{
	GList *i, *j;

	lasso_foreach(i, metadata->ServiceContext)
		lasso_foreach(j, ((LassoIdWsf2DiscoServiceContext*)i->data)->EndpointContext)

			lasso_idwsf2_discovery_match_request_service_and_metadata2(
					discovery,
					requested_service,
					metadata,
					(LassoIdWsf2DiscoServiceContext*)i->data,
					(LassoIdWsf2DiscoEndpointContext*)j->data, eprs);

}

static gint
lasso_idwsf2_discovery_validate_request_query(LassoIdWsf2Discovery *discovery)
{
	LassoIdWsf2DiscoQuery *query;
	LassoIdWsf2DiscoQueryResponse *query_response;
	GList *eprs = NULL;
	int rc = 0;

	/* Build EPRs */
	query = (LassoIdWsf2DiscoQuery*)discovery->parent.parent.request;
	lasso_foreach_full_begin(LassoIdWsf2DiscoRequestedService*, requested_service, i,
			query->RequestedService)
		lasso_foreach_full_begin(LassoIdWsf2DiscoSvcMetadata*, metadata, j,
				discovery->private_data->metadatas)
			lasso_idwsf2_discovery_match_request_service_and_metadata(discovery, requested_service,
					metadata, &eprs);
		lasso_foreach_full_end()
	lasso_foreach_full_end()

	if (eprs) {
		query_response = lasso_idwsf2_disco_query_response_new();
		query_response->Status = lasso_idwsf2_util_status_new_with_code(
				LASSO_IDWSF2_DISCOVERY_STATUS_CODE_OK, NULL);
		query_response->EndpointReference = eprs;
		lasso_check_good_rc(lasso_idwsf2_profile_init_response(&discovery->parent));
		lasso_soap_envelope_add_to_body(
				lasso_idwsf2_profile_get_soap_envelope_response(&discovery->parent),
				(LassoNode*)query_response);
		discovery->parent.parent.response = &query_response->parent;
	} else {
		return lasso_idwsf2_discovery_fail_request(discovery,
				LASSO_IDWSF2_DISCOVERY_STATUS_CODE_NO_RESULTS, NULL);
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_discovery_validate_md_register:
 * @discovery: a #LassoIdWsf2Discovery
 *
 * Process received metadata register request.
 * If successful, register the service metadata into the discovery service.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
static gint
lasso_idwsf2_discovery_validate_md_register(LassoIdWsf2Discovery *discovery)
{
	LassoIdWsf2Profile *profile = NULL;
	LassoIdWsf2DiscoSvcMDRegisterResponse *response = NULL;
	LassoSoapEnvelope *envelope = NULL;
	LassoIdWsf2DiscoSvcMDRegister *request = NULL;
	GList *SvcMD = NULL;
	GList *SvcMDs = NULL;
	int rc = 0;

	profile = LASSO_IDWSF2_PROFILE(discovery);
	lasso_release_list_of_gobjects(discovery->private_data->metadatas);
	request = (LassoIdWsf2DiscoSvcMDRegister*)profile->parent.request;

	lasso_release_list_of_gobjects(discovery->private_data->metadatas);
	/* Allocate SvcMDIDs and add the metadatas */
	for (SvcMD = request->SvcMD; SvcMD != NULL; SvcMD = g_list_next(SvcMD)) {
		if (LASSO_IS_IDWSF2_DISCO_SVC_METADATA(SvcMD->data)) {
			lasso_list_add_gobject(discovery->private_data->metadatas, SvcMD->data);
			lasso_assign_new_string(
					LASSO_IDWSF2_DISCO_SVC_METADATA(
						SvcMD->data)->svcMDID,
					lasso_build_unique_id(32));
		}
	}

	response = lasso_idwsf2_disco_svc_md_register_response_new();
	response->Status =
		lasso_idwsf2_util_status_new_with_code(LASSO_IDWSF2_DISCOVERY_STATUS_CODE_OK, NULL);
	for (SvcMDs = discovery->private_data->metadatas; SvcMDs != NULL; SvcMDs = g_list_next(SvcMDs)) {
		lasso_list_add_string(response->SvcMDID,
				LASSO_IDWSF2_DISCO_SVC_METADATA(SvcMDs->data)->svcMDID);
	}

	lasso_check_good_rc(lasso_idwsf2_profile_init_response(&discovery->parent));
	envelope = lasso_idwsf2_profile_get_soap_envelope_response(profile);
	lasso_soap_envelope_add_to_body(envelope, &response->parent);
	lasso_assign_gobject(profile->parent.response, response);
cleanup:
	lasso_release_gobject(response);
	return rc;
}

/**
 * lasso_idwsf2_discovery_validate_request:
 * @discovery: a #LassoIdWsf2Discovery object
 *
 * Accept the discovery request, and produce the response.
 *
 * Return value: 0 on success; or a negative value otherwise.
 */
gint
lasso_idwsf2_discovery_validate_request(LassoIdWsf2Discovery *discovery)
{
	LassoIdWsf2DiscoSvcMDAssociationAddResponse *md_association_add_response;
	LassoIdWsf2DiscoSvcMDAssociationDeleteResponse *md_association_delete_response;
	LassoIdWsf2DiscoSvcMDAssociationQueryResponse *md_association_query_response;
	LassoIdWsf2DiscoSvcMDQueryResponse *md_query_response;
	LassoIdWsf2DiscoSvcMDQuery *md_query;
	LassoIdWsf2DiscoSvcMDDeleteResponse *md_delete_response;
	LassoIdWsf2DiscoSvcMDReplaceResponse *md_replace_response;
	LassoNode *response = NULL;
	int rc = 0;
	GList *i;
	LassoIdWsf2UtilStatus **status = NULL;

	lasso_bad_param(IDWSF2_DISCOVERY, discovery);
	switch (lasso_idwsf2_discovery_get_request_type(discovery)) {
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY:
			lasso_check_good_rc(lasso_idwsf2_discovery_validate_request_query(discovery));
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER:
			lasso_check_good_rc(lasso_idwsf2_discovery_validate_md_register(discovery));
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY:
			md_query_response = lasso_idwsf2_disco_svc_md_query_response_new();
			md_query = (LassoIdWsf2DiscoSvcMDQuery*)discovery->parent.parent.request;
			response = (LassoNode*)md_query_response;
			if (md_query->SvcMDID) {
				lasso_foreach(i, discovery->private_data->metadatas) {
					LassoIdWsf2DiscoSvcMetadata *metadata = i->data;
					if (LASSO_IS_IDWSF2_DISCO_SVC_METADATA(metadata)
						&& _string_list_contains(md_query->SvcMDID, metadata->svcMDID)) {
						lasso_list_add_gobject(md_query_response->SvcMD, i->data);
					}
				}
			} else {
				lasso_assign_list_of_gobjects(md_query_response->SvcMD,
						discovery->private_data->metadatas);
			}
			status = &md_query_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REPLACE:
			md_replace_response = lasso_idwsf2_disco_svc_md_replace_response_new();
			response = (LassoNode*)md_replace_response;
			status = &md_replace_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE:
			md_delete_response = lasso_idwsf2_disco_svc_md_delete_response_new();
			response = (LassoNode*)md_delete_response;
			status = &md_delete_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD:
			md_association_add_response =
				lasso_idwsf2_disco_svc_md_association_add_response_new();
			response = (LassoNode*)md_association_add_response;
			status = &md_association_add_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE:
			md_association_delete_response =
				lasso_idwsf2_disco_svc_md_association_delete_response_new();
			response = (LassoNode*)md_association_delete_response;
			status = &md_association_delete_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY:
			md_association_query_response =
				lasso_idwsf2_disco_svc_md_association_query_response_new();
			response = (LassoNode*)md_association_query_response;
			lasso_foreach(i, discovery->private_data->svcmdids) {
				lasso_list_add_string(md_association_query_response->SvcMDID,
						i->data);
			}
			status = &md_association_query_response->Status;
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_UNKNOWN:
		default:
			lasso_idwsf2_discovery_fail_request(discovery, NULL, NULL);
			rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
			break;
	}
	if (response) {
		LassoSoapEnvelope *envelope =
			lasso_idwsf2_profile_get_soap_envelope_response(&discovery->parent);
		lasso_assign_new_gobject(discovery->parent.parent.response, response);
		lasso_soap_envelope_add_to_body(envelope, response);
	}

	if (status) {
		lasso_assign_new_gobject(*status,
				lasso_idwsf2_util_status_new_with_code(
					LASSO_IDWSF2_DISCOVERY_STATUS_CODE_OK, NULL));
	}

cleanup:
	return rc;
}

static gint
lasso_idwsf2_discovery_process_metadata_register_response_msg(LassoIdWsf2Discovery *discovery)
{
	LassoIdWsf2Profile *profile;
	LassoIdWsf2DiscoSvcMDRegisterResponse *response;
	LassoIdWsf2DiscoSvcMDRegister *request;
	GList *i, *j;
	int rc = 0;

	profile  = &discovery->parent;
	lasso_extract_node_or_fail(request, profile->parent.request, IDWSF2_DISCO_SVC_MD_REGISTER,
			LASSO_PROFILE_ERROR_MISSING_REQUEST);

	response = (LassoIdWsf2DiscoSvcMDRegisterResponse*)profile->parent.response;

	goto_cleanup_if_fail_with_rc(
			LASSO_IS_IDWSF2_DISCO_SVC_MD_REGISTER_RESPONSE(response),
			LASSO_PROFILE_ERROR_INVALID_RESPONSE);
	lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(response->Status));
	goto_cleanup_if_fail_with_rc(g_list_length(response->SvcMDID) ==
			g_list_length(request->SvcMD), LASSO_PROFILE_ERROR_INVALID_RESPONSE);
	/* Check IDs */
	i = response->SvcMDID;
	lasso_foreach(i, response->SvcMDID) {
		if (i->data == NULL || ((char*)i->data)[0] == '\0') {
			rc = LASSO_PROFILE_ERROR_INVALID_RESPONSE;
			goto cleanup;
		}
	}

	/* Assign IDs to metadatas */
	i = response->SvcMDID;
	j = request->SvcMD;
	while (i && j) {
		lasso_assign_string(((LassoIdWsf2DiscoSvcMetadata*)j->data)->svcMDID,
				i->data);
		i = i->next;
		j = j->next;
	}
	if (discovery->private_data && discovery->private_data->metadatas != request->SvcMD) {
		lasso_assign_list_of_gobjects(discovery->private_data->metadatas, request->SvcMD);
	}
cleanup:
	return rc;
}


/**
 * lasso_idwsf2_discovery_add_requested_service:
 * @discovery: a #LassoIdWsf2Discovery
 * @service_types:(element-type utf8)(allow-none): the service type (or data profile) requested
 * @provider_ids:(element-type utf8)(allow-none): the providers ids to select
 * @options:(element-type utf8)(allow-none): the options to select
 * @security_mechanisms:(element-type utf8)(allow-none): the security mechanisms to select
 * @frameworks:(element-type utf8)(allow-none): the ID-WSF framework version to select
 * @actions:(element-type utf8)(allow-none): the actions to select
 * @result_type:(allow-none)(default LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_NONE): how to filter
 * the generated EPRs
 * @req_id:(allow-none): an eventual ID to put on the request, that can be matched with the
 * generated EndpointReferences
 *
 * Add a new request to find some specific services associated to the current principal at the
 * discovery service.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_discovery_add_requested_service(LassoIdWsf2Discovery *discovery,
	GList *service_types, GList *provider_ids, GList *options, GList *security_mechanisms,
	GList *frameworks, GList *actions, LassoIdWsf2DiscoveryQueryResultType result_type,
	const char *req_id)
{
	LassoIdWsf2DiscoRequestedService *service;

	lasso_bad_param(IDWSF2_DISCOVERY, discovery);
	const char *result_type_s = NULL;


	service = lasso_idwsf2_disco_requested_service_new();
	lasso_assign_list_of_strings(service->ServiceType, service_types);
	lasso_assign_list_of_strings(service->ProviderID, provider_ids);
	lasso_assign_list_of_strings(service->Framework, frameworks);
	lasso_assign_list_of_strings(service->Action, actions);
	lasso_assign_list_of_strings(service->SecurityMechID, security_mechanisms);
	lasso_assign_list_of_gobjects(service->Options, options);
	switch (result_type) {
		case LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_BEST:
			result_type_s = LASSO_IDWSF2_DISCOVERY_RESULT_TYPE_BEST;
			break;
		case LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_ALL:
			result_type_s = LASSO_IDWSF2_DISCOVERY_RESULT_TYPE_ALL;
			break;
		case LASSO_IDWSF2_DISCOVERY_QUERY_RESULT_TYPE_ONLY_ONE:
			result_type_s = LASSO_IDWSF2_DISCOVERY_RESULT_TYPE_ONLY_ONE;
			break;
		default:
			break;
	}
	lasso_assign_string(service->resultsType, result_type_s);
	lasso_assign_string(service->reqID, req_id);

	lasso_list_add_new_gobject(discovery->private_data->requested_services, service);
	return 0;
}

/**
 * lasso_idwsf2_discovery_process_response_msg:
 * @discovery: a #LassoIdWsf2Discovery object
 * @msg: a string containing the response messages
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_discovery_process_response_msg(LassoIdWsf2Discovery *discovery,
		const char *msg)
{
	LassoIdWsf2DiscoSvcMDAssociationAddResponse *md_association_add_response;
	LassoIdWsf2DiscoSvcMDAssociationDeleteResponse *md_association_delete_response;
	LassoIdWsf2DiscoSvcMDAssociationQueryResponse *md_association_query_response;
	LassoIdWsf2DiscoSvcMDQueryResponse *md_query_response;
	LassoIdWsf2DiscoSvcMDDeleteResponse *md_delete_response;
	LassoIdWsf2DiscoSvcMDReplaceResponse *md_replace_response;
	LassoIdWsf2DiscoQueryResponse *query_response;
	LassoProfile *profile;
	LassoNode *response;
	int rc = 0;

	lasso_bad_param(IDWSF2_DISCOVERY, discovery);
	profile = &discovery->parent.parent;

	lasso_check_good_rc(lasso_idwsf2_profile_process_response_msg(&discovery->parent, msg));
	response = profile->response;

	switch (lasso_idwsf2_discovery_get_request_type(discovery)) {
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_QUERY:
			if (! LASSO_IS_IDWSF2_DISCO_QUERY_RESPONSE(response))
				goto bad_response;
			query_response = (LassoIdWsf2DiscoQueryResponse*)response;
			rc = lasso_idwsf2_discovery_status2rc(query_response->Status);
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REGISTER:
			rc = lasso_idwsf2_discovery_process_metadata_register_response_msg(
					discovery);
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_QUERY:
			if (! LASSO_IDWSF2_DISCO_SVC_MD_QUERY_RESPONSE(response))
				goto bad_response;
			md_query_response = (LassoIdWsf2DiscoSvcMDQueryResponse*)response;
			lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(
						md_query_response->Status));
			lasso_assign_list_of_gobjects(discovery->private_data->metadatas,
					md_query_response->SvcMD);
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_REPLACE:
			if (! LASSO_IDWSF2_DISCO_SVC_MD_REPLACE_RESPONSE(response))
				goto bad_response;
			md_replace_response = (LassoIdWsf2DiscoSvcMDReplaceResponse*)response;
			lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(
						md_replace_response->Status));
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_DELETE:
			if (! LASSO_IDWSF2_DISCO_SVC_MD_DELETE_RESPONSE(response))
				goto bad_response;
			md_delete_response = (LassoIdWsf2DiscoSvcMDDeleteResponse*)response;
			lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(
						md_delete_response->Status));
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_ADD:
			if (! LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_RESPONSE(response))
				goto bad_response;
			md_association_add_response =
				(LassoIdWsf2DiscoSvcMDAssociationAddResponse*)response;
			lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(
						md_association_add_response->Status));
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_DELETE:
			if (! LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_DELETE_RESPONSE(response))
				goto bad_response;
			md_association_delete_response =
				(LassoIdWsf2DiscoSvcMDAssociationDeleteResponse*)response;
			lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(
						md_association_delete_response->Status));
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_MD_ASSOCIATION_QUERY:
			if (! LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_QUERY_RESPONSE(response))
				goto bad_response;
			md_association_query_response =
				(LassoIdWsf2DiscoSvcMDAssociationQueryResponse*)response;
			lasso_check_good_rc(lasso_idwsf2_discovery_status2rc(
						md_association_query_response->Status));
			lasso_assign_list_of_strings(discovery->private_data->svcmdids,
					md_association_query_response->SvcMDID);
			break;
		case LASSO_IDWSF2_DISCOVERY_REQUEST_TYPE_UNKNOWN:
		default:
			rc = LASSO_PROFILE_ERROR_INVALID_REQUEST;
			break;
	}
cleanup:
	return rc;
bad_response:
	return LASSO_PROFILE_ERROR_INVALID_RESPONSE;
}

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoIdWsf2Discovery *discovery = LASSO_IDWSF2_DISCOVERY(object);
	if (discovery->private_data->dispose_has_run == TRUE)
		return;
	discovery->private_data->dispose_has_run = TRUE;
	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoIdWsf2Discovery *discovery = LASSO_IDWSF2_DISCOVERY(object);
	lasso_release(discovery->private_data);
	discovery->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

static void
instance_init(LassoIdWsf2Discovery *discovery)
{
	discovery->private_data = g_new0(LassoIdWsf2DiscoveryPrivate, 1);
	discovery->private_data->dispose_has_run = FALSE;
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoIdWsf2Discovery *discovery = (LassoIdWsf2Discovery*)node;

	if (! LASSO_IS_IDWSF2_PROFILE(node))
		return NULL;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);

	if (xmlnode && discovery->private_data) {
		LassoIdWsf2DiscoveryPrivate *pdata = discovery->private_data;
		if (pdata->metadatas) {
			xmlNode *metadatas;
			GList *i;
			metadatas = xmlNewChild(xmlnode, NULL, BAD_CAST LASSO_IDWSF2_DISCOVERY_ELEMENT_METADATAS, NULL);
			lasso_foreach(i, pdata->metadatas) {
				xmlAddChild(metadatas, lasso_node_get_xmlNode(i->data, lasso_dump));
			}
		}
		if (pdata->requested_services) {
			xmlNode *requested_services;
			GList *i;
			requested_services = xmlNewChild(xmlnode, NULL, BAD_CAST
					LASSO_IDWSF2_DISCOVERY_ELEMENT_REQUESTED_SERVICES, NULL);
			lasso_foreach(i, pdata->requested_services) {
				xmlAddChild(requested_services, lasso_node_get_xmlNode(i->data, lasso_dump));
			}
		}
	}

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdWsf2Discovery *discovery = (LassoIdWsf2Discovery*)node;
	xmlNode *metadatas_node, *requested_services_node;
	LassoIdWsf2DiscoveryPrivate *pdata;

	if (! LASSO_IS_IDWSF2_DISCOVERY(discovery))
		return LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ;

	parent_class->init_from_xml(node, xmlnode);

	if (xmlnode == NULL)
		return LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;

	metadatas_node = xmlSecFindChild(xmlnode,
			BAD_CAST LASSO_IDWSF2_DISCOVERY_ELEMENT_METADATAS,
			BAD_CAST LASSO_LASSO_HREF);
	requested_services_node = xmlSecFindChild(xmlnode,
			BAD_CAST LASSO_IDWSF2_DISCOVERY_ELEMENT_REQUESTED_SERVICES,
			BAD_CAST LASSO_LASSO_HREF);

	if (! discovery->private_data) {
		discovery->private_data = g_new0(LassoIdWsf2DiscoveryPrivate, 1);
	}
	pdata = discovery->private_data;

	if (metadatas_node) {
		xmlNode *it;
		for (it = xmlSecGetNextElementNode(metadatas_node->children);
				it != NULL; 
				it = xmlSecGetNextElementNode(it->next)) {
			LassoIdWsf2DiscoSvcMetadata *metadata;
			metadata = (LassoIdWsf2DiscoSvcMetadata*)lasso_node_new_from_xmlNode(it);
			if (! LASSO_IS_IDWSF2_DISCO_SVC_METADATA(metadata)) {
				lasso_release_gobject(metadata);
				goto error;
			}
			lasso_list_add_new_gobject(pdata->metadatas, metadata);
		}
	}
	if (requested_services_node) {
		xmlNode *it;
		for (it = xmlSecGetNextElementNode(requested_services_node->children);
				it != NULL; 
				it = xmlSecGetNextElementNode(it->next)) {
			LassoIdWsf2DiscoRequestedService *metadata;
			metadata = (LassoIdWsf2DiscoRequestedService*)lasso_node_new_from_xmlNode(it);
			if (! LASSO_IS_IDWSF2_DISCO_REQUESTED_SERVICE(metadata)) {
				lasso_release_gobject(metadata);
				goto error;
			}
			lasso_list_add_new_gobject(pdata->requested_services, metadata);
		}
	}

	return 0;
error:
	return LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;
}

static void
class_init(LassoIdWsf2DiscoveryClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	lasso_node_class_set_nodename(LASSO_NODE_CLASS(klass), "IdWsf2Discovery");
	lasso_node_class_set_ns(LASSO_NODE_CLASS(klass), LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
	klass->parent.parent.parent.get_xmlNode = get_xmlNode;
	klass->parent.parent.parent.init_from_xml = init_from_xml;

}

GType
lasso_idwsf2_discovery_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoIdWsf2DiscoveryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2Discovery),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_IDWSF2_PROFILE,
				"LassoIdWsf2Discovery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_discovery_new:
 * @server:(allow-none):a #LassoServer object, for resolving ProviderID names
 *
 * Create a new #LassoIdWsf2Discovery.
 *
 * Return value: a newly created #LassoIdWsf2Discovery object; or NULL if an error occured.
 **/
LassoIdWsf2Discovery*
lasso_idwsf2_discovery_new(LassoServer *server)
{
	LassoIdWsf2Discovery *discovery = NULL;

	discovery = g_object_new(LASSO_TYPE_IDWSF2_DISCOVERY, NULL);
	discovery->parent.parent.server = lasso_ref(server);

	return discovery;
}
