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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>

#include <lasso/xml/saml_attribute_value.h>

#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <lasso/xml/saml-2.0/samlp2_name_id_policy.h>

#include <lasso/xml/id-wsf-2.0/disco_query.h>
#include <lasso/xml/id-wsf-2.0/disco_requested_service.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_md_register.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_md_register_response.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_md_association_add.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_md_association_add_response.h>
#include <lasso/xml/id-wsf-2.0/disco_svc_md_association_add_response.h>
#include <lasso/xml/id-wsf-2.0/disco_abstract.h>
#include <lasso/xml/id-wsf-2.0/disco_providerid.h>
#include <lasso/xml/id-wsf-2.0/disco_service_type.h>
#include <lasso/xml/id-wsf-2.0/disco_security_context.h>
#include <lasso/xml/id-wsf-2.0/sec_token.h>

#include <lasso/xml/ws/wsa_endpoint_reference.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/provider.h>
#include <lasso/id-ff/providerprivate.h>

#include <lasso/id-wsf-2.0/discovery.h>
#include <lasso/id-wsf-2.0/wsf2_profile.h>
#include <lasso/id-wsf-2.0/identity.h>
#include <lasso/id-wsf-2.0/server.h>
#include <lasso/id-wsf-2.0/session.h>

struct _LassoIdWsf2DiscoveryPrivate
{
	gboolean dispose_has_run;
	GList *new_entry_ids;
	char *security_mech_id;
};

/*****************************************************************************/
/* public methods */
/*****************************************************************************/


/**
 * lasso_discovery_destroy:
 * @discovery: a LassoDiscovery
 * 
 * Destroys LassoDiscovery objects created with lasso_discovery_new() or
 * lasso_discovery_new_from_dump().
 **/
void
lasso_idwsf2_discovery_destroy(LassoIdWsf2Discovery *discovery)
{
	g_object_unref(G_OBJECT(discovery));
}

gchar*
lasso_idwsf2_discovery_metadata_register_self(LassoIdWsf2Discovery *discovery,
	const gchar *service_type, const gchar *abstract,
	const gchar *soap_endpoint, const gchar *svcMDID)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoProvider *provider;
	gchar *provider_id;
	LassoIdWsf2DiscoSvcMetadata *metadata;
	char unique_id[33];

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery), NULL);
	g_return_val_if_fail(service_type != NULL, NULL);
	g_return_val_if_fail(abstract != NULL, NULL);
	g_return_val_if_fail(soap_endpoint != NULL, NULL);

	provider = LASSO_PROVIDER(profile->server);
	provider_id = provider->ProviderID;

	metadata = lasso_idwsf2_disco_svc_metadata_new_full(
		service_type, abstract, provider_id, soap_endpoint);

	if (svcMDID != NULL) {
		metadata->svcMDID = g_strdup(svcMDID);
	} else {
		/* Build a unique SvcMDID */
		lasso_build_random_sequence(unique_id, 32);
		unique_id[32] = 0;
		metadata->svcMDID = g_strdup(unique_id);
	}

	/* Add the metadata into the server object */
	lasso_server_add_svc_metadata(profile->server, metadata);

	return g_strdup(metadata->svcMDID);
}

gint
lasso_idwsf2_discovery_init_metadata_register(LassoIdWsf2Discovery *discovery,
	const gchar *service_type, const gchar *abstract,
	const gchar *disco_provider_id, const gchar *soap_endpoint)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoSvcMDRegister *metadata_register;
	LassoProvider *provider;
	gchar *sp_provider_id;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(service_type != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(abstract != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(disco_provider_id != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(soap_endpoint != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* Get the providerId of this SP */
	provider = LASSO_PROVIDER(profile->server);
	sp_provider_id = provider->ProviderID;

	/* Get a MetadataRegister node */
	metadata_register = lasso_idwsf2_disco_svc_md_register_new_full(
			service_type, abstract, sp_provider_id, soap_endpoint);

	/* Create a request with this xml node */
	lasso_wsf2_profile_init_soap_request(profile, LASSO_NODE(metadata_register),
		LASSO_IDWSF2_DISCO_HREF);

	/* FIXME : Get the url of the disco service where we must send the soap request */
	/* profile->msg_url = g_strdup(disco_provider_id); */

	return 0;
}

gint
lasso_idwsf2_discovery_process_metadata_register_msg(LassoIdWsf2Discovery *discovery,
	const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoSvcMDRegister *request;
	LassoIdWsf2DiscoSvcMDRegisterResponse *response;
	LassoSoapEnvelope *envelope;
	char unique_id[33];
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Process request */
	res = lasso_wsf2_profile_process_soap_request_msg(profile, message);

	if (! LASSO_IS_IDWSF2_DISCO_SVC_MD_REGISTER(profile->request)) {
		res = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* If the request has been correctly processed, */
	/* put interesting data into the discovery object */
	if (res == 0) {
		request = LASSO_IDWSF2_DISCO_SVC_MD_REGISTER(profile->request);
		/* FIXME : foreach on the list instead */
		if (request != NULL && request->metadata_list != NULL) {
			discovery->metadata =
				LASSO_IDWSF2_DISCO_SVC_METADATA(request->metadata_list->data);
			/* Build a unique SvcMDID */
			lasso_build_random_sequence(unique_id, 32);
			unique_id[32] = 0;
			discovery->metadata->svcMDID = g_strdup(unique_id);
			/* Add the metadata into the server object */
			lasso_server_add_svc_metadata(profile->server, discovery->metadata);
		}
	}

	/* Build response */
	response = lasso_idwsf2_disco_svc_md_register_response_new();

	if (res == 0) {
		response->Status = lasso_util_status_new(LASSO_DISCO_STATUS_CODE_OK);
		/* FIXME : foreach here as well */
		response->SvcMDID = g_list_append(response->SvcMDID,
			g_strdup(discovery->metadata->svcMDID));
	} else {
		response->Status = lasso_util_status_new(LASSO_DISCO_STATUS_CODE_FAILED);
		/* XXX : May add secondary status codes here */
	}

	envelope = profile->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return res;
}

gint
lasso_idwsf2_discovery_process_metadata_register_response_msg(LassoIdWsf2Discovery *discovery,
	const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoSvcMDRegisterResponse *response;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Process request */
	res = lasso_wsf2_profile_process_soap_response_msg(profile, message);

	if (! LASSO_IS_IDWSF2_DISCO_SVC_MD_REGISTER_RESPONSE(profile->response)) {
		res = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* If the response has been correctly processed, */
	/* put interesting data into the discovery object */
	if (res == 0) {
		response = LASSO_IDWSF2_DISCO_SVC_MD_REGISTER_RESPONSE(profile->response);
		/* FIXME : foreach on the list instead */
		if (response->SvcMDID != NULL) {
			discovery->svcMDID = g_strdup(response->SvcMDID->data);
		} else {
			res = LASSO_IDWSF2_DISCOVERY_ERROR_SVC_METADATA_REGISTER_FAILED;
		}
	}

	return res;
}


gint
lasso_idwsf2_discovery_init_metadata_association_add(LassoIdWsf2Discovery *discovery,
	const gchar *svcMDID)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoSession *session = profile->session;
	LassoIdWsf2DiscoSvcMDAssociationAdd *md_association_add;
	LassoWsAddrEndpointReference *epr;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(svcMDID != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);

	/* Build a MetadataRegister node */
	md_association_add = lasso_idwsf2_disco_svc_md_association_add_new();
	md_association_add->SvcMDID = g_list_append(md_association_add->SvcMDID, g_strdup(svcMDID));

	/* Create a request with this xml node */
	lasso_wsf2_profile_init_soap_request(profile, LASSO_NODE(md_association_add),
		LASSO_IDWSF2_DISCO_HREF);

	epr = lasso_session_get_endpoint_reference(session, LASSO_IDWSF2_DISCO_HREF);
	if (epr != NULL) {
		profile->msg_url = g_strdup(epr->Address->content);
	}

	return 0;
}

gint
lasso_idwsf2_discovery_process_metadata_association_add_msg(LassoIdWsf2Discovery *discovery,
	const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoSvcMDAssociationAddResponse *response;
	LassoSoapEnvelope *envelope;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Process request */
	res = lasso_wsf2_profile_process_soap_request_msg(profile, message);

	if (! LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD(profile->request)) {
		res = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* Build response */
	response = lasso_idwsf2_disco_svc_md_association_add_response_new();

	/* Default is Failed, will be OK when metadatas are registered */
	response->Status = lasso_util_status_new(LASSO_DISCO_STATUS_CODE_FAILED);

	envelope = profile->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return res;
}

gint
lasso_idwsf2_discovery_register_metadata(LassoIdWsf2Discovery *discovery)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoSvcMDAssociationAdd *request;
	LassoIdWsf2DiscoSvcMDAssociationAddResponse *response;
	LassoIdentity *identity;
	LassoSoapEnvelope *envelope;
	GList *i;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
		
	/* verify if identity already exists else create it */
	if (profile->identity == NULL) {
		profile->identity = lasso_identity_new();
	}
	identity = profile->identity;

	if (! LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD(profile->request)) {
		res = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* If the request has been correctly processed, */
	/* put interesting data into the discovery object */
	request = LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD(profile->request);
	/* Copy the service metadatas with given svcMDIDs into the identity object */
	for (i = g_list_first(request->SvcMDID); i != NULL; i = g_list_next(i)) {
		lasso_identity_add_svc_md_id(identity, (gchar *)(i->data));
	}

	if (res == 0) {
		envelope = profile->soap_envelope_response;
		for (i = g_list_first(envelope->Body->any); i != NULL; i = g_list_next(i)) {
			if (LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_RESPONSE(i->data)) {
				response =
					LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_RESPONSE(i->data);
				response->Status->code = g_strdup(LASSO_DISCO_STATUS_CODE_OK);
				break;
			}
		}
	}

	return res;
}

gint
lasso_idwsf2_discovery_process_metadata_association_add_response_msg(
	LassoIdWsf2Discovery *discovery, const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoSvcMDAssociationAddResponse *response;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Process response */
	res = lasso_wsf2_profile_process_soap_response_msg(profile, message);
	if (res != 0) {
		return res;
	}

	if (! LASSO_IS_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_RESPONSE(profile->response)) {
		return LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* Check response status code */
	response = LASSO_IDWSF2_DISCO_SVC_MD_ASSOCIATION_ADD_RESPONSE(profile->response);
	if (response->Status == NULL || response->Status->code == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}
	if (strcmp(response->Status->code, "OK") != 0) {
		return LASSO_IDWSF2_DISCOVERY_ERROR_SVC_METADATA_ASSOCIATION_ADD_FAILED;
	}

	return 0;
}

/**
 * lasso_idwsf2_discovery_init_query
 * @discovery: a #LassoIdWsf2Discovery
 *
 * Initializes a disco:Query message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_idwsf2_discovery_init_query(LassoIdWsf2Discovery *discovery, const gchar *security_mech_id)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoSession *session = profile->session;
	LassoWsAddrEndpointReference *epr;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);

	if (profile->request) {
		lasso_node_destroy(LASSO_NODE(profile->request));
	}
	profile->request = LASSO_NODE(lasso_idwsf2_disco_query_new());

	lasso_wsf2_profile_init_soap_request(profile, profile->request, LASSO_IDWSF2_DISCO_HREF);
	
	epr = lasso_session_get_endpoint_reference(session, LASSO_IDWSF2_DISCO_HREF);
	if (epr != NULL) {
		profile->msg_url = g_strdup(epr->Address->content);
	}

	return 0;
}

gint
lasso_idwsf2_discovery_add_requested_service_type(LassoIdWsf2Discovery *discovery,
	const gchar *service_type)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdWsf2DiscoQuery *query;
	LassoIdWsf2DiscoRequestedService *service;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCO_QUERY(profile->request),
		LASSO_PROFILE_ERROR_MISSING_REQUEST);

	query = LASSO_IDWSF2_DISCO_QUERY(profile->request);
	service = lasso_idwsf2_disco_requested_service_new();
	service->ServiceType = g_list_append(service->ServiceType, g_strdup(service_type));
	query->RequestedService = g_list_append(query->RequestedService, service);

	return 0;
}

static LassoWsAddrEndpointReference*
lasso_idwsf2_discovery_build_query_response_epr(LassoIdWsf2DiscoRequestedService *service,
	LassoIdentity *identity, LassoServer *server)
{
	gchar *service_type = NULL;
	GList *svcMDIDs;
	GList *svcMDs;
	LassoIdWsf2DiscoSvcMetadata *svcMD;
	LassoWsAddrEndpointReference *epr;
	LassoWsAddrMetadata *metadata;
	LassoIdWsf2DiscoSecurityContext *security_context;
	LassoIdWsf2SecToken *sec_token;
	LassoSaml2Assertion *assertion_identity_token;
	LassoSaml2Subject *subject;
	LassoFederation* federation;

	if (service != NULL && service->ServiceType != NULL && service->ServiceType->data != NULL) {
		service_type = (gchar *)service->ServiceType->data;
	} else {
		/* Can only search for service type at the moment */
		return NULL;
	}

	svcMDIDs = lasso_identity_get_svc_md_ids(identity);
	svcMDs = lasso_server_get_svc_metadatas_with_id_and_type(server, svcMDIDs, service_type);
	if (svcMDs == NULL) {
		return NULL;
	}

	/* FIXME : foreach on the whole list and build an epr for each svcMD */
	svcMD = svcMDs->data;

	if (svcMD == NULL || svcMD->ServiceContext == NULL
			|| svcMD->ServiceContext->EndpointContext == NULL) {
		return NULL;
	}

	/* Build EndpointReference */

	epr = lasso_wsa_endpoint_reference_new();

	epr->Address = lasso_wsa_attributed_uri_new_with_string(
		svcMD->ServiceContext->EndpointContext->Address);

	metadata = lasso_wsa_metadata_new();

	/* Abstract */
	metadata->any = g_list_append(metadata->any,
 		lasso_idwsf2_disco_abstract_new_with_content(svcMD->Abstract));
 	/* ProviderID */
	metadata->any = g_list_append(metadata->any,
 		lasso_idwsf2_disco_providerid_new_with_content(svcMD->ProviderID));
 	/* ServiceType */
	metadata->any = g_list_append(metadata->any,
 		lasso_idwsf2_disco_service_type_new_with_content(
 			svcMD->ServiceContext->ServiceType));
	/* Framework */
	if (svcMD->ServiceContext->EndpointContext->Framework != NULL) {
		metadata->any = g_list_append(metadata->any,
			g_object_ref(svcMD->ServiceContext->EndpointContext->Framework));
	}
	
	/* Identity token */	
	federation = lasso_identity_get_federation(identity, svcMD->ProviderID);
	if (federation != NULL) {
		assertion_identity_token = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());

		/* Identity token Subject */
		subject = LASSO_SAML2_SUBJECT(lasso_saml2_subject_new());
		if (federation->remote_nameIdentifier != NULL) {
			subject->NameID = g_object_ref(federation->remote_nameIdentifier);
		} else {
			subject->NameID = g_object_ref(federation->local_nameIdentifier);
		}
		assertion_identity_token->Subject = subject;

		sec_token = LASSO_IDWSF2_SEC_TOKEN(lasso_idwsf2_sec_token_new());
		sec_token->any = LASSO_NODE(assertion_identity_token);
		
		security_context = LASSO_IDWSF2_DISCO_SECURITY_CONTEXT(
			lasso_idwsf2_disco_security_context_new());
		security_context->SecurityMechID = g_list_append(
			security_context->SecurityMechID, g_strdup(LASSO_SECURITY_MECH_TLS_BEARER));
		security_context->Token = g_list_append(security_context->Token, sec_token);
		
		metadata->any = g_list_append(metadata->any, security_context);
	}

	epr->Metadata = metadata;
	
	return epr;
}

gint
lasso_idwsf2_discovery_process_query_msg(LassoIdWsf2Discovery *discovery, const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoIdentity *identity = profile->identity;
	LassoServer *server = profile->server;
	LassoIdWsf2DiscoQuery* request;
	LassoIdWsf2DiscoQueryResponse *response;
	LassoSoapEnvelope *envelope;
	LassoIdWsf2DiscoRequestedService *service = NULL;
	LassoWsAddrEndpointReference *epr;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Process request */
	res = lasso_wsf2_profile_process_soap_request_msg(profile, message);

	if (! LASSO_IS_IDWSF2_DISCO_QUERY(profile->request)) {
		res = LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	} else if (! LASSO_IS_IDENTITY(identity)) {
		res = LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND;
	}

	/* If the request has been correctly processed, */
	/* put interesting data into the discovery object */
	if (res == 0) {
		request = LASSO_IDWSF2_DISCO_QUERY(profile->request);
		/* FIXME : foreach on the list instead */
		if (request->RequestedService != NULL) {
			service = LASSO_IDWSF2_DISCO_REQUESTED_SERVICE(
				request->RequestedService->data);
		}
		if (service == NULL) {
			res = LASSO_IDWSF2_DISCOVERY_ERROR_MISSING_REQUESTED_SERVICE;
		}
	}

	/* Build response */
	response = lasso_idwsf2_disco_query_response_new();

	if (res == 0) {
		response->Status = lasso_util_status_new(LASSO_DISCO_STATUS_CODE_OK);
		/* FIXME : foreach here as well */
		epr = lasso_idwsf2_discovery_build_query_response_epr(service, identity, server);
		if (epr != NULL) {
			response->EndpointReference =
				g_list_append(response->EndpointReference, epr);
		}
		/* XXX : Should probably check if the epr contains a SecurityContext, */
		/* otherwise return a "federation not found" error code */
	} else {
		response->Status = lasso_util_status_new(LASSO_DISCO_STATUS_CODE_FAILED);
		/* XXX : May add secondary status codes here */
	}

	envelope = profile->soap_envelope_response;
	envelope->Body->any = g_list_append(envelope->Body->any, response);

	return res;
}

gint
lasso_idwsf2_discovery_process_query_response_msg(LassoIdWsf2Discovery *discovery,
	const gchar *message)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoSession *session = profile->session;
	LassoIdWsf2DiscoQueryResponse *response;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);

	/* Process request */
	res = lasso_wsf2_profile_process_soap_response_msg(profile, message);
	if (res != 0) {
		return res;
	}

	if (! LASSO_IS_IDWSF2_DISCO_QUERY_RESPONSE(profile->response)) {
		return LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
	}

	/* Check response status code */
	response = LASSO_IDWSF2_DISCO_QUERY_RESPONSE(profile->response);
	if (response->Status == NULL || response->Status->code == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_STATUS_CODE;
	}
	if (strcmp(response->Status->code, "OK") != 0) {
		return LASSO_IDWSF2_DISCOVERY_ERROR_SVC_METADATA_ASSOCIATION_ADD_FAILED;
	}

	/* If the response has been correctly processed, */
	/* put interesting data into the discovery object */
	response = LASSO_IDWSF2_DISCO_QUERY_RESPONSE(profile->response);
	/* FIXME : foreach on the list instead */
	if (response->EndpointReference != NULL
			&& response->EndpointReference->data != NULL) {
		lasso_session_add_endpoint_reference(session,
			response->EndpointReference->data);
	}

	return 0;
}

/**
 * lasso_idwsf2_discovery_get_service:
 * @discovery: a #LassoIdWsf2Discovery
 * @service_type: the requested service type
 *
 * After a disco:query message, creates a #LassoIdWsf2DataService instance for the
 * requested @service_type.
 *
 * Return value: a newly created #LassoIdWsf2DataService object; or NULL if an
 *     error occured.
 **/
LassoIdWsf2DataService*
lasso_idwsf2_discovery_get_service(LassoIdWsf2Discovery *discovery, const gchar *service_type)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(discovery);
	LassoSession *session = profile->session;
	LassoIdWsf2DiscoQueryResponse *response;
	LassoWsAddrEndpointReference *epr = NULL;
	LassoIdWsf2DataService *service;

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCOVERY(discovery), NULL);

	g_return_val_if_fail(LASSO_IS_SESSION(session), NULL);

	g_return_val_if_fail(LASSO_IS_IDWSF2_DISCO_QUERY_RESPONSE(profile->response), NULL);

	response = LASSO_IDWSF2_DISCO_QUERY_RESPONSE(profile->response);

	/* FIXME : foreach on the list instead */
	if (response->EndpointReference != NULL && response->EndpointReference->data != NULL) {
		epr = LASSO_WSA_ENDPOINT_REFERENCE(response->EndpointReference->data);
	} else {
		return NULL;
	}

	service = lasso_idwsf2_data_service_new_full(profile->server, epr);

	/* Copy session to service object (used to get assertion identity token from the session) */
 	LASSO_WSF2_PROFILE(service)->session = g_object_ref(session);

	return service;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)"Discovery");
	xmlSetProp(xmlnode, (xmlChar*)"DiscoveryDumpVersion", (xmlChar*)"2");

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) return rc;

	return 0;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

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
	g_free(discovery->private_data);
	discovery->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2Discovery *discovery)
{
	discovery->metadata = NULL;
	discovery->svcMDID = NULL;
	discovery->private_data = g_new0(LassoIdWsf2DiscoveryPrivate, 1);
	discovery->private_data->dispose_has_run = FALSE;
}

static void
class_init(LassoIdWsf2DiscoveryClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
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
		};

		this_type = g_type_register_static(LASSO_TYPE_WSF2_PROFILE,
						   "LassoIdWsf2Discovery", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_discovery_new:
 * @server: the #LassoServer
 *
 * Creates a new #LassoIdWsf2Discovery.
 *
 * Return value: a newly created #LassoIdWsf2Discovery object; or NULL if an error
 *      occured.
 **/
LassoIdWsf2Discovery*
lasso_idwsf2_discovery_new(LassoServer *server)
{
	LassoIdWsf2Discovery *discovery = NULL;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	discovery = g_object_new(LASSO_TYPE_IDWSF2_DISCOVERY, NULL);
	LASSO_WSF2_PROFILE(discovery)->server = g_object_ref(server);

	return discovery;
}
