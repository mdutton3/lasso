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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/utils.h>

#include <lasso/id-wsf/wsf_profile.h>
#include <lasso/id-wsf/wsf_profile_private.h>
#include <lasso/id-wsf/discovery.h>
#include <lasso/id-wsf/utils.h>
#include <lasso/xml/disco_modify.h>
#include <lasso/xml/soap_fault.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/soap_binding_processing_context.h>
#include <lasso/xml/wsse_security.h>
#include <lasso/xml/saml_assertion.h>
#include <lasso/xml/saml_authentication_statement.h>
#include <lasso/xml/saml_subject_statement_abstract.h>
#include <lasso/xml/saml_subject.h>
#include <lasso/xml/ds_key_info.h>
#include <lasso/xml/ds_key_value.h>
#include <lasso/xml/ds_rsa_key_value.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/providerprivate.h>
#include <lasso/id-ff/sessionprivate.h>

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Server", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, server) },
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, request) },
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, response) },
	{ "SOAP-Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, soap_envelope_request) },
	{ "SOAP-Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, soap_envelope_response) },
	{ "MsgUrl", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsfProfile, msg_url) },
	{ "MsgBody", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsfProfile, msg_body) },
	{ "Identity", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, identity) },
	{ "Session", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, session) },
	{ NULL, 0, 0}
};

/*
 * lasso_wsf_profile_get_fault:
 * @profile: a #LassoWsfProfile
 *
 * Get the current fault present in profile private datas
 */
LassoSoapFault*
lasso_wsf_profile_get_fault(LassoWsfProfile *profile)
{
	return profile->private_data->fault;
}

/**
 * lasso_wsf_profile_comply_with_saml_authentication:
 * @profile: a #LassoWsfProfile
 *
 * Return value: 0 if an assertion was found and a signature corresponding to the
 * key given as a subject confirmation in the assertion is generated, an error
 * code otherwise.
 */
static gint
lasso_wsf_profile_comply_with_saml_authentication(LassoWsfProfile *profile)
{
	LassoSoapEnvelope *soap;
	LassoSoapHeader *header;
	LassoWsseSecurity *wsse_security;
	LassoSamlAssertion *assertion;
	LassoSession *session;
	LassoDiscoDescription *description;
	GList *credentialRefs;

	wsse_security = lasso_wsse_security_new();
	session = profile->session;
	description = lasso_wsf_profile_get_description(profile);
	/* Lookup in the session the credential ref from the description and
         * add them to the SOAP header wsse:Security. */
	/* FIXME: should we really add every credentials to the message ? */
	credentialRefs = description->CredentialRef;
	while (credentialRefs) {
		char *ref = (char*)credentialRefs->data;
		assertion = LASSO_SAML_ASSERTION(
			lasso_session_get_assertion_by_id(session, ref));
		if (LASSO_IS_SAML_ASSERTION(assertion)) {
			g_list_add_gobject(wsse_security->any, assertion);
		}
		credentialRefs = g_list_next(credentialRefs);
	}
	soap = profile->soap_envelope_request;
	header = soap->Header;
	g_list_add_gobject(header->Other, wsse_security);
	return 0;
}

/** 
 * lasso_wsf_profile_comply_with_security_mechanism:
 * @profile: a #LassoWsfProfile
 *
 * UNCOMPLETE.
 *
 * Return value: 0 if complyiing with the current security mechanism was
 * successfull.
 */
static gint
lasso_wsf_profile_comply_with_security_mechanism(LassoWsfProfile *profile)
{
	char *sec_mech_id;

	g_return_val_if_invalid_param(WSF_PROFILE, profile, 
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	
	sec_mech_id = profile->private_data->security_mech_id;
	if (lasso_security_mech_id_is_saml_authentication(sec_mech_id)) {
		return lasso_wsf_profile_comply_with_saml_authentication(profile);
	}
	if (sec_mech_id == NULL 
		|| lasso_security_mech_id_is_null_authentication(sec_mech_id)) {
		return 0;
	}
	return LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM;
}

static LassoSoapEnvelope*
lasso_wsf_profile_build_soap_envelope_internal(const char *refToMessageId, const char *providerId)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;
	LassoSoapBindingCorrelation *correlation;
	gchar *messageId, *timestamp;

	/* Body */
	body = lasso_soap_body_new();
	body->id = lasso_build_unique_id(32);
	envelope = lasso_soap_envelope_new(body);

	/* Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	/* Correlation */
	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
	correlation->id = lasso_build_unique_id(32);
	if (refToMessageId != NULL)
		correlation->refToMessageID = g_strdup(refToMessageId);
	header->Other = g_list_append(header->Other, correlation);

	/* Provider */
	if (providerId) {
		LassoSoapBindingProvider *provider = lasso_soap_binding_provider_new(providerId);
		provider->id = lasso_build_unique_id(32);
		header->Other = g_list_append(header->Other, provider);
	}

	return envelope;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_wsf_profile_move_credentials:
 * @src: a #LassoWsfProfile containing the credentials
 * @dest: the #LassoWsfProfile where to add the credentials
 *
 * OBSOLETE: Do nothin.
 *
 * Return value: 0.
 */ 
gint
lasso_wsf_profile_move_credentials(LassoWsfProfile *src, LassoWsfProfile *dest)
{
	return 0;
}

/** 
 * lasso_wsf_profile_add_credential:
 * @profile: a #LassoWsfProfile
 * @credential: an #xmlNode containing credential informations
 *
 * OBSOLETE: Do nothing.
 *
 * Return value: 0.
 */
gint
lasso_wsf_profile_add_credential(LassoWsfProfile *profile, xmlNode *credential)
{
	return 0;
}

/*
 * lasso_wsf_profile_get_description_autos:
 * @si: a #LassoDiscoServiceInstance
 * @security_mech_id: the URI of a liberty security mechanism
 *
 * Traverse the service instance descriptions and find one which supports the
 * given security mechanism.
 *
 * Return value: a #LassoDiscoDescription that supports security_mech_id, NULL
 * otherwise.
 */
LassoDiscoDescription*
lasso_wsf_profile_get_description_auto(LassoDiscoServiceInstance *si, const gchar *security_mech_id)
{
	GList *iter, *iter2;
	LassoDiscoDescription *description;

	g_return_val_if_fail(si, NULL);
	g_return_val_if_fail(security_mech_id, NULL);

	iter = si->Description;
	while (iter) {
		description = LASSO_DISCO_DESCRIPTION(iter->data);
		iter2 = description->SecurityMechID;
		while (iter2) {
			if (strcmp(security_mech_id, iter2->data) == 0)
				return description;
			iter2 = iter2->next;
		}
		iter = iter->next;
	}

	return NULL;
}

/**
 * lasso_wsf_profile_set_description_from_offering:
 * @profile: a #LassoWsfProfile
 * @offering: a #LassoDiscoResourceOffering containing descriptions
 * @security_mech_id: an URL representing the wished security mechanism, if NULL take the first descriptions
 *
 * Setup the LassoWsfProfile for a given security mechanism.
 *
 * Return value: 0 if a corresponding description was found,
 * LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION if no description with the
 * given security mechanism was found.
 */
gint
lasso_wsf_profile_set_description_from_offering(
	LassoWsfProfile *profile,
	LassoDiscoResourceOffering *offering,
	const gchar *security_mech_id)
{
	LassoDiscoDescription *description = NULL;

	g_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_invalid_param(DISCO_RESOURCE_OFFERING, offering,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	if (security_mech_id == NULL) {
		if (offering->ServiceInstance &&
		    offering->ServiceInstance->Description) {
			description = LASSO_DISCO_DESCRIPTION(
					offering->ServiceInstance->Description->data);
		}
	} else {
		description = lasso_discovery_get_description_auto(
				offering, security_mech_id);
	}
	if (description == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_SERVICE_DESCRIPTION;
	}
	lasso_wsf_profile_set_description(profile, description);
	return 0;
}

/**
 * lasso_wsf_profile_set_security_mech_id:
 * @profile: the #LassoWsfProfile object
 * @securit_mech_id: a char* string representing the chosen security mech id.
 *
 * Set the security mechanism to use. Currently only SAML and NULL mechanism
 * are supported for authentication. Transposrt is not handled by lasso so all
 * are supported.
 *
 * List of supported mechanism ids:
 * LASSO_SECURITY_MECH_NULL or "urn:liberty:security:2003-08:null:null"
 * LASSO_SECURITY_MECH_SAML or "urn:liberty:security:2003-08:null:SAML"
 * LASSO_SECURITY_MECH_TLS or "urn:liberty:security:2003-08:TLS:null"
 * LASSO_SECURITY_MECH_TLS_SAML or "urn:liberty:security:2003-08:TLS:SAML"
 * LASSO_SECURITY_MECH_CLIENT_TLS or "urn:liberty:security:2003-08:ClientTLS:null"
 * LASSO_SECURITY_MECH_CLIENT_TLS_SAML or "urn:liberty:security:2003-08:ClientTLS:SAML"
 *
 * Return value: 0 if the security mechanism is supported by this #LassoWsfProfile
 * object, an error code otherwise.
 */
gint
lasso_wsf_profile_set_security_mech_id(LassoWsfProfile *profile,
	const char *security_mech_id)
{
	g_return_val_if_invalid_param(WSF_PROFILE, profile,
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	if (lasso_security_mech_id_is_saml_authentication(security_mech_id)
			|| lasso_security_mech_id_is_null_authentication(security_mech_id)) {
		g_assign_string(profile->private_data->security_mech_id, security_mech_id);
		if (profile->private_data->offering) {
			return lasso_wsf_profile_set_description_from_offering(
				profile,
				profile->private_data->offering,
				security_mech_id);
		}
	}
	return LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM;
}

/**
 * lasso_wsf_profile_get_security_mech_id:
 * @profile: the #LassoWsfProfile object
 *
 * Return value: the current security mechanism id for this object.
 */
const char *
lasso_wsf_profile_get_security_mech_id(LassoWsfProfile *profile)
{
	g_return_val_if_invalid_param(WSF_PROFILE, profile,
		NULL);

	return profile->private_data->security_mech_id;
}

/**
 * lasso_wsf_profile_set_description:
 * @profile: the #LassoWsfProfile
 * @description: a #LassoDiscoDescription
 *
 * Set the currently registered #LassoDiscoDescription, that permits to locate
 * the endpoint and the security mechanism to use for the next ID-WSF request.
 */
void
lasso_wsf_profile_set_description(LassoWsfProfile *profile, LassoDiscoDescription *description)
{
	g_assign_gobject(profile->private_data->description, description);
}

/** 
 * lasso_wsf_profile_get_description:
 * @profile: a #LassoWsfProfile 
 *
 * Returns the currently registered #LassoDiscoDescription, that permits to
 * locate the endpoint and the security mechanism to use for the next ID-WSF
 * request.
 *
 * Return value: a #LassoDiscoDescriptio or NULL if none is present.
 */
LassoDiscoDescription *
lasso_wsf_profile_get_description(LassoWsfProfile *profile)
{
	return profile->private_data->description;
}

/**
 * lasso_wsf_profile_get_resource_offering:
 * @profile: the #LassoWsfProfile object
 *
 * Returns the ResourceOffering setupt with this profile object.
 *
 * Return value: a #LassoDiscoResourceOffering if one was setup during
 * construction, NULL otherwise.
 */
LassoDiscoResourceOffering *
lasso_wsf_profile_get_resource_offering(LassoWsfProfile *profile)
{
	return profile->private_data->offering;
}

/**
 * lasso_wsf_profile_set_resource_offering:
 * @profile:
 * @offering:
 *
 *
 */
void
lasso_wsf_profile_set_resource_offering(LassoWsfProfile *profile, LassoDiscoResourceOffering *offering)
{
	g_assign_gobject(profile->private_data->offering, offering);
}

/**
 * lasso_wsf_profile_build_soap_envelope:
 * @refToMessageId: a char* string and the eventual MessageId of a SOAP request
 * we are responding to.
 * @providerId: a char* string and the eventual providerID of a web service
 * provider we intend to send this soap message to.
 *
 * Build the a #LassoSoapEnvelope as a template for a future SOAP message
 * containing the headers recommended by the ID-WSF 1.0 specification.
 *
 * Return value: a new #LassoSoapEnvelope if construction was successfull.
 */
LassoSoapEnvelope*
lasso_wsf_profile_build_soap_envelope(const char *refToMessageId, const char *providerId)
{
	return lasso_wsf_profile_build_soap_envelope_internal(refToMessageId, providerId);
}


/**
 * lasso_wsf_profile_is_principal_online():
 * @profile: a #LassoWsfProfile
 *
 * OBSOLETE: do nothing.
 *
 * Return value: FALSE.
 **/
gboolean
lasso_wsf_profile_principal_is_online(LassoWsfProfile *profile)
{
	return FALSE;
}

/**
 * lasso_wsf_profile_set_principal_online():
 * @profile: a #LassoWsfProfile
 * @status : a char* representing status of principal.
 *
 * OBSOLETE: do nothing.
 *
 **/
void
lasso_wsf_profile_set_principal_status(LassoWsfProfile *profile, const char *status)
{
}

/**
 * lasso_wsf_profile_set_principal_online():
 * @profile: a #LassoWsfProfile
 *
 * OBSOLETE: do nothing.
 *
 **/
void
lasso_wsf_profile_set_principal_online(LassoWsfProfile *profile)
{
}

/**
 * lasso_wsf_profile_set_principal_offline():
 * @profile: a #LassoWsfProfile
 *
 * Set the principal status as offline.
 *
 **/
void
lasso_wsf_profile_set_principal_offline(LassoWsfProfile *profile)
{
}

/**
 * lasso_wsf_profile_get_identity:
 * @profile: a #LassoWsfProfile
 *
 * Gets the identity bound to @profile.
 *
 * Return value: the identity or NULL if it none was found.  The #LassoIdentity
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoIdentity*
lasso_wsf_profile_get_identity(LassoWsfProfile *profile)
{
	if (profile->identity && g_hash_table_size(profile->identity->federations))
		return profile->identity;
	return NULL;
}


/**
 * lasso_wsf_profile_get_session:
 * @profile: a #LassoWsfProfile
 *
 * Gets the session bound to @profile.
 *
 * Return value: the session or NULL if it none was found.  The #LassoSession
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoSession*
lasso_wsf_profile_get_session(LassoWsfProfile *profile)
{
	if (profile->session == NULL)
		return NULL;

	if (lasso_session_is_empty(profile->session))
		return NULL;

	return profile->session;
}


/**
 * lasso_wsf_profile_is_identity_dirty:
 * @profile: a #LassoWsfProfile
 *
 * Checks whether identity has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if identity has changed
 **/
gboolean
lasso_wsf_profile_is_identity_dirty(LassoWsfProfile *profile)
{
	return (profile->identity && profile->identity->is_dirty);
}


/**
 * lasso_wsf_profile_is_session_dirty:
 * @profile: a #LassoWsfProfile
 *
 * Checks whether session has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if session has changed
 **/
gboolean
lasso_wsf_profile_is_session_dirty(LassoWsfProfile *profile)
{
	return (profile->session && profile->session->is_dirty);
}


/**
 * lasso_wsf_profile_set_identity_from_dump:
 * @profile: a #LassoWsfProfile
 * @dump: XML identity dump
 *
 * Builds a new #LassoIdentity object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_wsf_profile_set_identity_from_dump(LassoWsfProfile *profile, const gchar *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->identity = lasso_identity_new_from_dump(dump);
	if (profile->identity == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP);

	return 0;
}


/**
 * lasso_wsf_profile_set_session_from_dump:
 * @profile: a #LassoWsfProfile
 * @dump: XML session dump
 *
 * Builds a new #LassoSession object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_wsf_profile_set_session_from_dump(LassoWsfProfile *profile, const gchar  *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->session = lasso_session_new_from_dump(dump);
	if (profile->session == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_SESSION_DUMP);
	profile->session->is_dirty = FALSE;

	return 0;
}

/**
 * lasso_wsf_profile_init_soap_request:
 * @profile: a #LassoWsfProfile to initialize for a SOAP request 
 * @request: a #LassoNode object containing the body for the SOAP request, can be NULL.
 *
 * Build the SOAP envelope for a request to and ID-WSF 1.0 web service and set
 * the body of the request to request. The reference to request is not stolen i.e
 * the ref count of request is increased by one after this call.
 *
 * Return value: 0 if initialization was successfull.
 */
gint
lasso_wsf_profile_init_soap_request(LassoWsfProfile *profile, LassoNode *request)
{
	LassoSoapEnvelope *envelope;
	char *providerID = NULL;

	g_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (profile->server) {
		providerID = profile->server->parent.ProviderID;
	}
	envelope = lasso_wsf_profile_build_soap_envelope_internal(NULL, providerID);
	profile->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, request);
	profile->request = request;
	return lasso_wsf_profile_comply_with_security_mechanism(profile);
}

/** 
 * lasso_wsf_profile_build_soap_request_msg:
 * @profile: the #LassoWsfProfile object
 *
 * Create the char* string containing XML document for the SOAP ID-WSF request
 * and eventually sign with the local public depending on the security
 * mechanism requested.
 *
 * Return value: 0 if construction is successfull.
 */
gint
lasso_wsf_profile_build_soap_request_msg(LassoWsfProfile *profile)
{
	LassoSoapEnvelope *envelope;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	xmlDoc *doc = NULL;
	xmlNode *envelope_node = NULL;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request),
		LASSO_SOAP_ERROR_MISSING_ENVELOPE);

	envelope = profile->soap_envelope_request;
	doc = xmlNewDoc((xmlChar*)"1.0");
	envelope_node = lasso_node_get_xmlNode(LASSO_NODE(envelope), FALSE);
	xmlDocSetRootElement(doc, envelope_node);
	/* Sign request if necessary */
	// lasso_wsf_profile_sign_request(profile, doc)
	/* Dump soap request */
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, envelope_node, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);
	xmlFreeDoc(doc);

	return 0;
}

/** 
 * lasso_wsf_profile_build_soap_response_msg:
 * @profile: the #LassoWsfProfile object
 *
 * Create the char* string containing XML document for the SOAP ID-WSF
 * response.
 *
 * Return value: 0 if construction is successfull.
 */
int
lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *profile)
{
	LassoSoapEnvelope *envelope;
	xmlNode *soap_envelope;
	xmlDoc *doc;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;

	g_return_val_if_invalid_param(WSF_PROFILE, profile, 
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	envelope = profile->soap_envelope_response;
	doc = xmlNewDoc((xmlChar*)"1.0");
	soap_envelope = lasso_node_get_xmlNode(LASSO_NODE(envelope), TRUE);
	xmlDocSetRootElement(doc, soap_envelope);
	/* FIXME: does we need signature ? */
	/* Dump soap response */
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, soap_envelope, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	xmlOutputBufferClose(buf);
	xmlFreeDoc(doc);

	return 0;
}

gint
lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile, const gchar *message,
					   const gchar *service_type, const gchar *security_mech_id)
{
	LassoSoapBindingCorrelation *correlation = NULL;
	LassoSoapEnvelope *envelope = NULL;
	gchar *messageId;
	int res = 0;
	xmlDoc *doc;
	GList *iter = NULL;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	doc = lasso_xml_parse_memory(message, strlen(message));

	/* Get soap request and his message id */
	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	profile->soap_envelope_request = envelope;
	profile->request = LASSO_NODE(envelope->Body->any->data);

	/* Get the correlation header */
	iter = envelope->Header->Other;
	while (iter && ! LASSO_IS_SOAP_BINDING_CORRELATION(iter->data)) {
		iter = iter->next;
	}
	if (iter) {
		correlation = LASSO_SOAP_BINDING_CORRELATION(iter->data);
	} 
	if (correlation == NULL || correlation->messageID == NULL) {
		return LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION;
	}
	messageId = correlation->messageID;

	/* Comply with security mechanism */
	if (security_mech_id == NULL 
	    || lasso_security_mech_id_is_null_authentication(security_mech_id)) {
		res = 0;
	} else {
		/** FIXME: add security mechanisms */
		res = LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM;
		goto exit;
	}

	/* Set soap response */
	envelope = lasso_wsf_profile_build_soap_envelope_internal(messageId,
		LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_WSF_PROFILE(profile)->soap_envelope_response = envelope;
exit:
	if (doc)
		xmlFreeDoc(doc);

	return res;
}

/** 
 * lasso_wsf_profile_process_soap_response_msg:
 * @profile: a #LassoWsfProfile object
 * @message: the textual representaition of a SOAP message
 *
 * Parse a SOAP response from an ID-WSF 1.0 service, 
 * eventually signal a SOAP fault.
 *
 * Return value: 0 if the processing of this message was successful.
 */
gint
lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile, const gchar *message)
{
	xmlDoc *doc;
	xmlNode *root;
	LassoNode *node;
	gint ret = 0;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), 
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, 
			LASSO_PARAM_ERROR_INVALID_VALUE);

	doc = lasso_xml_parse_memory(message, strlen(message));
	if (doc == NULL) {
		ret = critical_error(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);
		goto exit;
	}
	root = xmlDocGetRootElement(doc);
	/* Parse the message */
	node = lasso_node_new_from_xmlNode(root);
	if (LASSO_IS_SOAP_ENVELOPE(node)) {
		profile->soap_envelope_response = LASSO_SOAP_ENVELOPE(node);
		node = NULL;
	} else {
		ret = critical_error(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);
		goto exit;
	}
	profile->response = LASSO_NODE(profile->soap_envelope_response->Body->any->data);
	/* Signal soap fault specifically */
	if (LASSO_IS_SOAP_FAULT(profile->response)) {
		return LASSO_WSF_PROFILE_ERROR_SOAP_FAULT;
	}
exit:
	if (node) {
		g_object_unref(node);
	}
	if (doc) {
		xmlFreeDoc(doc);
	}
	return ret;
}

/**
 * lasso_wsf_profile_set_provider_soap_request:
 *
 * OBSOLETE: do nothing.
 *
 * Return value: NULL
 */
LassoSoapBindingProvider *lasso_wsf_profile_set_provider_soap_request(LassoWsfProfile *profile,
	const char *providerId)
{
	return NULL;
}

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);

	if (profile->private_data->dispose_has_run == TRUE)
		return;
	profile->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);
	g_free(profile->private_data);
	profile->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsfProfile *profile)
{
	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->soap_envelope_request = NULL;
	profile->soap_envelope_response = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
	
	profile->private_data = g_new0(LassoWsfProfilePrivate, 1);
}

static void
class_init(LassoWsfProfileClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "WsfProfile");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_wsf_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoWsfProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsfProfile),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsfProfile", &this_info, 0);
	}
	return this_type;
}

/** 
 * lasso_wsf_profile_init:
 * @profile: the #LassoWsfProfile to initialize
 * @server: a #LassoServer object to resolve provider IDs.
 * @offering: a #LassoDiscoResourceOffering for the 
 * targetted web service.
 *
 * Initialize a #LassoWsfProfile in order to handle or send
 * request to, an ID-WSF web service.
 *
 * Return: 0 if initialization was successfull.
 */
gint
lasso_wsf_profile_init(LassoWsfProfile *profile, 
		LassoServer *server, 
		LassoDiscoResourceOffering *offering)
{
	g_return_val_if_invalid_param(WSF_PROFILE, profile, 
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	/* FIXME: is a NULL server authorized ? */
	g_assign_gobject(profile->server, server);
	/* FIXME: is a NULL oferring authorized ? */
	g_assign_gobject(profile->private_data->offering, offering);

	return 0;
}


/**
 * lasso_wsf_profile_new:
 * @server: a #LassoServer object to lookup remote provider informations
 *
 * Create a new #WsfProfile with the given #LassoServer object.
 *
 * Return: a new #LassoWsfProfile if creation and initialization were
 * successfull, NULL otherwise.
 */
LassoWsfProfile*
lasso_wsf_profile_new(LassoServer *server)
{
	return lasso_wsf_profile_new_full(server, NULL);
}

/**
 * lasso_wsf_profile_new_full:
 * @server: a #LassoServer object to lookup remote provider informations.
 * @offering: a #LassoDiscoResourceOffering for the requested service.
 *
 * Create a new #WsfProfile with the given #LassoServer object and the given
 * #LassoDiscoResourceOffering.
 *
 * Return: a new #LassoWsfProfile if creation and initialization were
 * successfull, NULL otherwise.
 */
LassoWsfProfile*
lasso_wsf_profile_new_full(LassoServer *server, LassoDiscoResourceOffering *offering)
{
	LassoWsfProfile *profile = NULL;

	profile = g_object_new(LASSO_TYPE_WSF_PROFILE, NULL);
	if (lasso_wsf_profile_init(profile, server, offering)) {
		g_release_gobject(profile);
	}
	return profile;
}
