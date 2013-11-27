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

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/soap.h>

#include "../utils.h"

#include "wsf_profile.h"
#include "../xml/idwsf_strings.h"
#include "wsf_profile_private.h"
#include "discovery.h"
#include "wsf_utils.h"
#include "../xml/disco_modify.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/soap_binding_correlation.h"
#include "../xml/soap_binding_provider.h"
#include "../xml/soap_binding_processing_context.h"
#include "../xml/saml_assertion.h"
#include "../xml/saml_authentication_statement.h"
#include "../xml/saml_subject_statement_abstract.h"
#include "../xml/saml_subject.h"
#include "../xml/ds_key_info.h"
#include "../xml/ds_key_value.h"
#include "../xml/ds_rsa_key_value.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/soap-1.1/soap_detail.h"
#include "../xml/is_redirect_request.h"
#include "../xml/ws/wsse_security_header.h"


#include "../id-ff/server.h"
#include "../id-ff/providerprivate.h"
#include "../id-ff/sessionprivate.h"
#include "../xml/misc_text_node.h"

/**
 * SECTION:wsf_profile
 * @short_description: Base class for ID-WSF 1.0 services
 * @stability: Unstable
 *
 * Use this class to base your ID-WSF 1.0 services.
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoDiscoDescription* lasso_wsf_profile_get_description_auto(
		const LassoDiscoServiceInstance *si, const gchar *security_mech_id);
static gint lasso_wsf_profile_add_saml_signature(LassoWsfProfile *wsf_profile, xmlDoc *doc);
static LassoSoapBindingCorrelation* lasso_wsf_profile_utils_get_header_correlation(
		LassoSoapEnvelope *envelope);
static char* lasso_wsf_profile_utils_get_message_id(LassoSoapEnvelope *envelope);
static char* lasso_wsf_profile_utils_get_ref_message_id(LassoSoapEnvelope *envelope);

static struct XmlSnippet schema_snippets[] = {
	{ "Server", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, server), NULL, NULL, NULL},
	{ "Request", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, request), NULL, NULL, NULL},
	{ "Response", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, response), NULL, NULL, NULL},
	{ "SOAP-Request", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoWsfProfile, soap_envelope_request), NULL, NULL, NULL},
	{ "SOAP-Response", SNIPPET_NODE_IN_CHILD,
		G_STRUCT_OFFSET(LassoWsfProfile, soap_envelope_response), NULL, NULL, NULL},
	{ "MsgUrl", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsfProfile, msg_url), NULL, NULL, NULL},
	{ "MsgBody", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoWsfProfile, msg_body), NULL, NULL, NULL},
	{ "Identity", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, identity), NULL, NULL, NULL},
	{ "Session", SNIPPET_NODE_IN_CHILD, G_STRUCT_OFFSET(LassoWsfProfile, session), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoSoapBindingCorrelation*
lasso_wsf_profile_utils_get_header_correlation(LassoSoapEnvelope *envelope)
{
	LassoSoapHeader *header;
	GList *header_list;

	if (LASSO_IS_SOAP_HEADER(envelope->Header)) {
		header = envelope->Header;
	} else {
		goto cleanup;
	}
	lasso_foreach(header_list, header->Other)
	{
		if (LASSO_IS_SOAP_BINDING_CORRELATION(header_list->data)) {
			return (LassoSoapBindingCorrelation*)header_list->data;
		}
	}
cleanup:
	return NULL;
}

static char*
lasso_wsf_profile_utils_get_ref_message_id(LassoSoapEnvelope *envelope)
{
	LassoSoapBindingCorrelation *correlation_header;

	correlation_header = lasso_wsf_profile_utils_get_header_correlation(envelope);
	if (! correlation_header) {
		return NULL;
	}
	return correlation_header->refToMessageID;
}

static char*
lasso_wsf_profile_utils_get_message_id(LassoSoapEnvelope *envelope)
{
	LassoSoapBindingCorrelation *correlation_header;

	correlation_header = lasso_wsf_profile_utils_get_header_correlation(envelope);
	if (! correlation_header) {
		return NULL;
	}
	return correlation_header->messageID;
}
/**
 * lasso_wsf_profile_build_soap_fault_response_msg:
 * @profile: a #LassoWsfProfile
 * @rc: an error code from Lasso
 *
 * Build a new SOAP fault, eventually fill it with the given rc code
 */
gint
lasso_wsf_profile_build_soap_fault_response_msg(LassoWsfProfile *profile, gint rc)
{
	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	lasso_assign_new_gobject(profile->response, lasso_soap_fault_new());
	if (rc) {
		LassoMiscTextNode *node;

		if (rc == LASSO_PROFILE_ERROR_INVALID_MSG) {
			lasso_assign_string(LASSO_SOAP_FAULT(profile->response)->faultcode,
					LASSO_SOAP_ENV_PREFIX ":" LASSO_SOAP_FAULT_CODE_CLIENT);
		} else {
			lasso_assign_string(LASSO_SOAP_FAULT(profile->response)->faultcode,
					LASSO_SOAP_ENV_PREFIX ":" LASSO_SOAP_FAULT_CODE_SERVER);
		}
		lasso_assign_string(LASSO_SOAP_FAULT(profile->response)->faultstring,
				LASSO_SOAP_FAULT_STRING_SERVER);
		lasso_assign_new_gobject(LASSO_SOAP_FAULT(profile->response)->Detail, lasso_soap_detail_new());
		node = (LassoMiscTextNode*)lasso_misc_text_node_new();
		lasso_assign_string(node->content, lasso_strerror(rc));
		node->name = "LassoError";
		node->ns_href = LASSO_LASSO_HREF;
		node->ns_prefix = LASSO_LASSO_PREFIX;
	}
	return rc;
}

/**
 * lasso_wsf_set_msg_url_from_description:
 * @profile: the #LassoWsfProfile object
 *
 * Initialize the @msgUrl attribute of the #LassoWsfProfile to the URL of the targetted web service.
 *
 * Return value: 0 if successful
 */
gint
lasso_wsf_profile_set_msg_url_from_description(LassoWsfProfile *wsf_profile)
{
	LassoDiscoDescription *description = NULL;
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(wsf_profile),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	description = lasso_wsf_profile_get_description(wsf_profile);
	if (description->Endpoint != NULL) {
		lasso_assign_string(wsf_profile->msg_url, description->Endpoint);
	} else {
		rc = LASSO_WSF_PROFILE_ERROR_MISSING_ENDPOINT;
	}
	lasso_release_gobject(description);
	return rc;
}

/* Documentation of g_list_find_custom say that list element is the first pointer,
 * and user_data the second */
static gboolean
is_of_type(gconstpointer a, gconstpointer b)
{
	GType typeid = (GType)b;

	if (a && G_IS_OBJECT(a)) {
		return G_OBJECT_TYPE(G_OBJECT(a)) == typeid;
	}
	return FALSE;
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
	LassoSoapEnvelope *soap = NULL;
	LassoSoapHeader *header = NULL;
	LassoWsSec1SecurityHeader *wsse_security = NULL;
	LassoSession *session = NULL;
	LassoDiscoDescription *description = NULL;
	GList *credentialRefs = NULL;
	gint rc = 0;
	GList *needle = NULL;

	lasso_bad_param(WSF_PROFILE, profile);
	lasso_extract_node_or_fail(session, profile->session, SESSION, LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);
	description = lasso_wsf_profile_get_description(profile);
	/* Lookup in the session the credential ref from the description and
	 * add them to the SOAP header wsse:Security. */
	/* FIXME: should we really add every credentials to the message, or only the one identifying
	 * us? */
	goto_cleanup_if_fail_with_rc(description != NULL, LASSO_WSF_PROFILE_ERROR_MISSING_DESCRIPTION);
	credentialRefs = description->CredentialRef;
	goto_cleanup_if_fail_with_rc(credentialRefs != NULL, LASSO_WSF_PROFILE_ERROR_MISSING_CREDENTIAL_REF);
	lasso_extract_node_or_fail(soap, profile->soap_envelope_request, SOAP_ENVELOPE, LASSO_SOAP_ERROR_MISSING_ENVELOPE);
	lasso_extract_node_or_fail(header, soap->Header, SOAP_HEADER, LASSO_SOAP_ERROR_MISSING_HEADER);
	needle = g_list_find_custom(header->Other, (gconstpointer)LASSO_TYPE_WSSE_SECURITY_HEADER,
			(GCompareFunc)is_of_type);
	if (needle) {
		lasso_assign_gobject(wsse_security, LASSO_WSSE_SECURITY_HEADER(needle->data));
	} else {
		wsse_security = lasso_wsse_security_header_new();
	}
	/* Comply with ID-WSF 1.0 specification */
	lasso_node_set_custom_namespace(LASSO_NODE(wsse_security), LASSO_WSSE_PREFIX,
			LASSO_WSSE_HREF);

	while (credentialRefs) {
		char *ref = (char*)credentialRefs->data;
		xmlNode *assertion = lasso_session_get_assertion_by_id(session, ref);
		goto_cleanup_if_fail_with_rc(assertion != NULL, LASSO_WSF_PROFILE_ERROR_MISSING_CREDENTIAL_REF);
		/* add an exact copy of the assertion in order to keep the IdP signature valid */
		lasso_list_add_new_gobject(wsse_security->any, lasso_misc_text_node_new_with_xml_node(assertion));
		credentialRefs = g_list_next(credentialRefs);
		lasso_release_xml_node(assertion);
	}
	if (needle == NULL) {
		lasso_list_add_gobject(header->Other, wsse_security);
	}
cleanup:
	lasso_release_gobject(wsse_security);
	lasso_release_gobject(description);
	return rc;
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

	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	sec_mech_id = profile->private_data->security_mech_id;
	if (lasso_security_mech_id_is_saml_authentication(sec_mech_id)) {
		return lasso_wsf_profile_comply_with_saml_authentication(profile);
	}
	if (lasso_security_mech_id_is_bearer_authentication(sec_mech_id)) {
		/* Same as SAML auth, add the tokens to wss:Security header, the difference is that
		 * later we won't add our own signature to the header */
		return lasso_wsf_profile_comply_with_saml_authentication(profile);
	}
	if (lasso_security_mech_id_is_null_authentication(sec_mech_id)) {
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
	body->Id = lasso_build_unique_id(32);
	envelope = lasso_soap_envelope_new(body);

	/* Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	/* Correlation */
	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
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
 * @Deprecated: Since 2.2.1
 *
 * Return value: 0.
 */
gint
lasso_wsf_profile_move_credentials(G_GNUC_UNUSED LassoWsfProfile *src, G_GNUC_UNUSED LassoWsfProfile *dest)
{
	return 0;
}

/**
 * lasso_wsf_profile_add_credential:
 * @profile: a #LassoWsfProfile
 * @credential: an #xmlNode containing credential informations
 *
 * @Deprecated: Since 2.2.1
 *
 * Return value: 0.
 */
gint
lasso_wsf_profile_add_credential(G_GNUC_UNUSED LassoWsfProfile *profile, G_GNUC_UNUSED xmlNode *credential)
{
	return 0;
}

/*
 * lasso_wsf_profile_get_description_auto:
 * @si: a #LassoDiscoServiceInstance
 * @security_mech_id: the URI of a liberty security mechanism
 *
 * Traverse the service instance descriptions and find one which supports the
 * given security mechanism.
 *
 * Return value: a #LassoDiscoDescription that supports security_mech_id, NULL
 * otherwise.
 */
static LassoDiscoDescription*
lasso_wsf_profile_get_description_auto(const LassoDiscoServiceInstance *si,
	const gchar *security_mech_id)
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
 * @security_mech_id: an URL representing the wished security mechanism,
 * if NULL take the first descriptions
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
	const LassoDiscoResourceOffering *offering,
	const gchar *security_mech_id)
{
	LassoDiscoDescription *description = NULL;

	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	lasso_return_val_if_invalid_param(DISCO_RESOURCE_OFFERING, offering,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	if (security_mech_id == NULL) {
		if (offering->ServiceInstance &&
			offering->ServiceInstance->Description) {
			description = LASSO_DISCO_DESCRIPTION(
					offering->ServiceInstance->Description->data);
		}
	} else {
		description = lasso_wsf_profile_get_description_auto(offering->ServiceInstance,
				security_mech_id);
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
 * @security_mech_id: a char* string representing the chosen security mech id.
 *
 * Set the security mechanism to use. Currently only SAML and NULL mechanism
 * are supported for authentication. Transport is not handled by lasso so all
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
	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (lasso_security_mech_id_is_saml_authentication(security_mech_id)
			|| lasso_security_mech_id_is_null_authentication(security_mech_id)) {
		lasso_assign_string(profile->private_data->security_mech_id, security_mech_id);
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
 * Return value:(transfer none): the current security mechanism id for this object.
 */
const char *
lasso_wsf_profile_get_security_mech_id(LassoWsfProfile *profile)
{
	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
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
	lasso_assign_gobject(profile->private_data->description, description);
}

/**
 * lasso_wsf_profile_get_description:
 * @profile: a #LassoWsfProfile
 *
 * Returns the currently registered #LassoDiscoDescription, that permits to
 * locate the endpoint and the security mechanism to use for the next ID-WSF
 * request.
 *
 * Return value:(transfer full): a #LassoDiscoDescriptio or NULL if none is present.
 */
LassoDiscoDescription *
lasso_wsf_profile_get_description(const LassoWsfProfile *profile)
{
	return lasso_ref(profile->private_data->description);
}

/**
 * lasso_wsf_profile_get_resource_offering:
 * @profile: the #LassoWsfProfile object
 *
 * Returns the ResourceOffering setupt with this profile object.
 *
 * Return value:(transfer full): a #LassoDiscoResourceOffering if one was setup during
 * construction, NULL otherwise.
 */
LassoDiscoResourceOffering *
lasso_wsf_profile_get_resource_offering(LassoWsfProfile *profile)
{
	return lasso_ref(profile->private_data->offering);
}

/**
 * lasso_wsf_profile_set_resource_offering:
 * @profile: a #LassoWsfProfile
 * @offering: a #LassoDiscoResourceOffering
 *
 * Set the Resssource Offering to setup this ID-WSF profile.
 *
 */
void
lasso_wsf_profile_set_resource_offering(LassoWsfProfile *profile,
	LassoDiscoResourceOffering *offering)
{
	lasso_assign_gobject(profile->private_data->offering, offering);
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
 * lasso_wsf_profile_get_identity:
 * @profile: a #LassoWsfProfile
 *
 * Gets the identity bound to @profile.
 *
 * Return value:(transfer none)(allow-none): the identity or NULL if it none was found.  The #LassoIdentity
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoIdentity*
lasso_wsf_profile_get_identity(const LassoWsfProfile *profile)
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
 * Return value:(transfer none)(allow-none): the session or NULL if it none was found. The
 * #LassoSession object is internally allocated and must not be freed by the caller.
 **/
LassoSession*
lasso_wsf_profile_get_session(const LassoWsfProfile *profile)
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
lasso_wsf_profile_is_identity_dirty(const LassoWsfProfile *profile)
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
lasso_wsf_profile_is_session_dirty(const LassoWsfProfile *profile)
{
	return (profile->session && lasso_session_is_dirty(profile->session));
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
 **/
gint
lasso_wsf_profile_init_soap_request(LassoWsfProfile *profile, LassoNode *request)
{
	LassoSoapEnvelope *envelope;
	char *providerID = NULL;

	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (profile->server) {
		providerID = profile->server->parent.ProviderID;
	}
	envelope = lasso_wsf_profile_build_soap_envelope_internal(NULL, providerID);
	lasso_assign_new_gobject(profile->soap_envelope_request, envelope);
	lasso_list_add_gobject(envelope->Body->any, request);
	lasso_assign_gobject(profile->request, request);
	return 0;
}

/**
 * lasso_wsf_profile_init_soap_response:
 * @profile: a #LassoWsfProfile object
 * @response: a #LassoNode object
 *
 * Build a new SOAP envelope containing response to current SOAP request
 */
gint
lasso_wsf_profile_init_soap_response(LassoWsfProfile *profile, LassoNode *response)
{
	char *providerID = NULL;
	LassoSoapEnvelope *envelope = NULL;

	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	if (profile->server) {
		providerID = profile->server->parent.ProviderID;
	}
	envelope = lasso_wsf_profile_build_soap_envelope_internal(lasso_wsf_profile_utils_get_message_id(profile->soap_envelope_request),
			providerID);
	lasso_assign_new_gobject(profile->soap_envelope_response, envelope);
	lasso_list_add_gobject(envelope->Body->any, response);
	lasso_assign_gobject(profile->response, response);
	return 0;
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
 **/
gint
lasso_wsf_profile_build_soap_request_msg(LassoWsfProfile *wsf_profile)
{
	LassoSoapEnvelope *envelope;
	xmlOutputBuffer *buf;
	xmlCharEncodingHandler *handler;
	xmlDoc *doc = NULL;
	xmlNode *envelope_node = NULL;
	char *sec_mech_id = NULL;
	int rc = 0;

	lasso_bad_param(WSF_PROFILE, wsf_profile);
	lasso_return_val_if_invalid_param(SOAP_ENVELOPE, wsf_profile->soap_envelope_request,
			LASSO_SOAP_ERROR_MISSING_ENVELOPE);

	rc = lasso_wsf_profile_comply_with_security_mechanism(wsf_profile);
	goto_cleanup_if_fail(rc == 0);
	envelope = wsf_profile->soap_envelope_request;
	doc = xmlNewDoc((xmlChar*)"1.0");
	envelope_node = lasso_node_get_xmlNode(LASSO_NODE(envelope), FALSE);
	xmlDocSetRootElement(doc, envelope_node);
	/* Sign request if necessary */
	sec_mech_id = wsf_profile->private_data->security_mech_id;
	if (lasso_security_mech_id_is_saml_authentication(sec_mech_id)) {
		rc = lasso_wsf_profile_add_saml_signature(wsf_profile, doc);
		if (rc != 0) {
			goto cleanup;
		}
	} else if (lasso_security_mech_id_is_bearer_authentication(sec_mech_id)) {
		// Nothing to do
	} else if (lasso_security_mech_id_is_null_authentication(sec_mech_id) == FALSE) {
		rc = LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM;
		goto cleanup;
	}

	/* Dump soap request */
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, envelope_node, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	wsf_profile->msg_body = g_strdup(
		(char*)(buf->conv ? buf->conv->content : buf->buffer->content));
	lasso_release_output_buffer(buf);
	rc = lasso_wsf_profile_set_msg_url_from_description(wsf_profile);

cleanup:
	lasso_release_doc(doc);
	return rc;
}

/**
 * lasso_wsf_profile_build_soap_response_msg:
 * @wsf_profile: a #LassoWsfProfile object
 *
 * Create the char* string containing XML document for the SOAP ID-WSF
 * response.
 *
 * Return value: 0 if construction is successfull.
 **/
gint
lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *wsf_profile)
{
	LassoSoapEnvelope *envelope = NULL;
	LassoSoapFault *soap_fault = NULL;
	int rc = 0;

	lasso_bad_param(WSF_PROFILE, wsf_profile);
	envelope = wsf_profile->soap_envelope_response;
	if (! LASSO_IS_SOAP_ENVELOPE(envelope)) {
		return LASSO_SOAP_ERROR_MISSING_ENVELOPE;
	}

	/* If SOAP fault replace response by the SOAP fault */
	if ((soap_fault = lasso_wsf_profile_get_soap_fault(wsf_profile))) {
		LassoSoapBody *body = NULL;
		lasso_extract_node_or_fail(body, envelope->Body, SOAP_BODY, LASSO_SOAP_ERROR_MISSING_BODY);
		lasso_release_list_of_gobjects(body->any);
		lasso_list_add_gobject(body->any, soap_fault);
	}

	lasso_assign_new_string(wsf_profile->msg_body,
			lasso_node_export_to_xml((LassoNode*)envelope));
cleanup:
	return rc;
}

/** FIXME: add support for security mechanisms SAML and Bearer. */
/**
 * lasso_wsf_profile_process_soap_request_msg:
 * @profile: a #LassoWsfProfile object
 * @message: a SOAP request message string
 * @security_mech_id: the security mechanism to apply
 *
 * Process an ID-WSF SOAP request, extract headers information, and check compliance with the
 * security mechanism.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile, const gchar *message,
	const gchar *security_mech_id)
{
	LassoSoapBindingCorrelation *correlation = NULL;
	LassoSoapEnvelope *envelope = NULL;
	gchar *messageId = NULL;
	int rc = 0;
	xmlDoc *doc = NULL;
	GList *iter = NULL;
	GList *node_list = NULL;

	lasso_bad_param(WSF_PROFILE, profile);
	lasso_null_param(message);

	g_return_val_if_fail(profile->private_data, LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT);
	lasso_wsf_profile_set_soap_fault(profile, NULL);

	doc = lasso_xml_parse_memory(message, strlen(message));
	goto_cleanup_if_fail_with_rc (doc != NULL, critical_error(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG));
	/* Get soap request and his message id */
	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc)));
	if (LASSO_IS_SOAP_ENVELOPE(envelope)) {
		lasso_assign_gobject(profile->soap_envelope_request, envelope);
	} else {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);
	}
	goto_cleanup_if_fail_with_rc(envelope != NULL, LASSO_SOAP_ERROR_MISSING_ENVELOPE);
	goto_cleanup_if_fail_with_rc(envelope->Body != NULL, LASSO_SOAP_ERROR_MISSING_BODY);
	if (envelope->Body->any && LASSO_IS_NODE(envelope->Body->any->data)) {
		lasso_assign_gobject(profile->request, LASSO_NODE(envelope->Body->any->data));
	} else {
		profile->request = NULL;
		rc = LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}

	/* Get the correlation header */
	goto_cleanup_if_fail_with_rc(envelope->Header != NULL, LASSO_SOAP_ERROR_MISSING_HEADER);
	for (iter = envelope->Header->Other; iter != NULL; iter = iter->next) {
		if (LASSO_IS_SOAP_BINDING_CORRELATION(iter->data)) {
			correlation = LASSO_SOAP_BINDING_CORRELATION(iter->data);
			break;
		}
	}
	goto_cleanup_if_fail_with_rc (correlation != NULL && correlation->messageID != NULL,
		LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION);
	messageId = correlation->messageID;

	/* Comply with security mechanism */
	if (lasso_security_mech_id_is_null_authentication(security_mech_id) == FALSE) {
		goto_cleanup_if_fail_with_rc(FALSE, LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM);
	}

	/* Extract the remote provider ID if present */
	if (LASSO_IS_SOAP_HEADER(envelope->Header)) {
		for (node_list = envelope->Header->Other;
				node_list; node_list = g_list_next(node_list)) {
			LassoSoapBindingProvider *node = node_list->data;

			if (LASSO_IS_SOAP_BINDING_PROVIDER(node)) {
				lasso_assign_string(profile->private_data->remote_provider_id,
						node->providerID);
				break; /* Only treat the first one */
			}
		}
	}

cleanup:
	lasso_release_gobject(envelope);
	lasso_release_doc(doc);

	return rc;
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
 **/
gint
lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile, const gchar *message)
{
	xmlDoc *doc = NULL;
	LassoSoapEnvelope *envelope = NULL;
	gint rc = 0;

	lasso_bad_param(WSF_PROFILE, profile);
	lasso_null_param(message);

	g_return_val_if_fail(profile->private_data, LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT);
	lasso_wsf_profile_set_soap_fault(profile, NULL);

	doc = lasso_xml_parse_memory(message, strlen(message));
	goto_cleanup_if_fail_with_rc (doc != NULL, critical_error(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG));
	envelope = (LassoSoapEnvelope*)lasso_node_new_from_xmlNode(xmlDocGetRootElement(doc));
	if (LASSO_IS_SOAP_ENVELOPE(envelope)) {
		lasso_assign_gobject(profile->soap_envelope_response, envelope);
	} else {
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);
	}
	goto_cleanup_if_fail_with_rc(envelope->Body != NULL, LASSO_SOAP_ERROR_MISSING_BODY);
	if (envelope->Body->any && LASSO_IS_NODE(envelope->Body->any->data)) {
		lasso_assign_gobject(profile->response, envelope->Body->any->data);
	} else {
		lasso_release_gobject(profile->response);
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_RESPONSE);
	}

	/* Check correlation header */
	goto_cleanup_if_fail_with_rc(
			lasso_wsf_profile_utils_get_header_correlation(
				profile->soap_envelope_response),
			LASSO_WSF_PROFILE_ERROR_MISSING_CORRELATION);

	/* Check message ID */
	{
		const char *message_id =
			lasso_wsf_profile_utils_get_message_id(profile->soap_envelope_request);
		const char *ref_message_id =
			lasso_wsf_profile_utils_get_ref_message_id(profile->soap_envelope_response);
		goto_cleanup_if_fail_with_rc(lasso_strisequal(message_id, ref_message_id),
				LASSO_WSF_PROFILE_ERROR_INVALID_OR_MISSING_REFERENCE_TO_MESSAGE_ID);
	}

	/* Signal soap fault specifically,
	 * find soap redirects. */
	if (LASSO_IS_SOAP_FAULT(profile->response)) {
		LassoSoapFault *fault = LASSO_SOAP_FAULT(profile->response);
		if (LASSO_IS_SOAP_DETAIL(fault->Detail)) {
		    LassoSoapDetail *detail = LASSO_SOAP_DETAIL(fault->Detail);
		    GList *iter = detail->any;
		    for (; iter; iter = g_list_next(iter)) {
			if (LASSO_IS_IS_REDIRECT_REQUEST(iter->data)) {
			    LassoIsRedirectRequest *redirect = LASSO_IS_REDIRECT_REQUEST(iter->data);
			    lasso_assign_string(profile->msg_url, redirect->redirectURL);
			    rc = LASSO_SOAP_ERROR_REDIRECT_REQUEST_FAULT;
			}
		    }

		}
		if (rc == 0) {
			rc = LASSO_WSF_PROFILE_ERROR_SOAP_FAULT;
		}
	}
cleanup:
	lasso_release_gobject(envelope);
	lasso_release_doc(doc);
	return rc;
}

/**
 * lasso_wsf_profile_set_provider_soap_request:
 *
 * @Deprecated: Since 2.2.1
 *
 * Return value: NULL
 **/
LassoSoapBindingProvider *
lasso_wsf_profile_set_provider_soap_request(G_GNUC_UNUSED LassoWsfProfile *profile,
	G_GNUC_UNUSED const char *providerId)
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
	lasso_release_string(profile->private_data->security_mech_id);
	lasso_release_gobject(profile->private_data->offering);
	lasso_release_gobject(profile->private_data->description);
	lasso_release_string(profile->private_data->remote_provider_id);
	lasso_release_gobject(profile->private_data->soap_fault);
	lasso_release_string(profile->private_data->status_code);
	profile->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(object);
	lasso_release(profile->private_data);
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
			NULL
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
	lasso_return_val_if_invalid_param(WSF_PROFILE, profile,
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	/* FIXME: is a NULL server authorized ? */
	lasso_assign_gobject(profile->server, server);
	/* FIXME: is a NULL oferring authorized ? */
	lasso_assign_gobject(profile->private_data->offering, offering);

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
		lasso_release_gobject(profile);
	}
	return profile;
}

/**
 * add_signature_template:
 * @server: a #LassoServer object
 * @doc: a #xmlDoc structure
 * @node a #xmlNode structure
 * @signature_ptr: an output argument for an #xmlNode structure
 *
 * Create a new XMLDSig template without any reference and return the created
 * Signature node. If node is not NULL add Signature as a last child to it. If @signature_ptr is not
 * NULL the template node is stored there.
 *
 * Return value: 0 if successful, LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED otherwise.
 */
static gint
add_signature_template(LassoServer *server, xmlDoc *doc, xmlNode *node, xmlNode **signature_ptr) {
	xmlNode *signature = NULL;
	gint rc = 0;

	switch (server->signature_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			signature = xmlSecTmplSignatureCreate(doc,
				xmlSecTransformExclC14NId,
				xmlSecTransformRsaSha1Id,
				NULL);
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			signature = xmlSecTmplSignatureCreate(doc,
				xmlSecTransformExclC14NId,
				xmlSecTransformDsaSha1Id,
				NULL);
			break;
		default:
			rc = LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED;
			goto cleanup;

	}

	/* Last steps... */
	if (signature_ptr) {
		*signature_ptr = signature;
	}
	if (node) {
		xmlAddChild(node, signature);
	}
cleanup:
	return rc;
}

static gint
add_reference_to_non_enveloping_id(xmlNode *signature, xmlChar *id)
{
	gint rc = 0;
	char *uri = NULL;
	xmlNode *reference = NULL;

	goto_cleanup_if_fail_with_rc(signature != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	goto_cleanup_if_fail_with_rc(id != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	uri = g_strdup_printf("#%s", id);
	reference = xmlSecTmplSignatureAddReference(signature,
			xmlSecTransformSha1Id, NULL, (xmlChar*)uri, NULL);
	/* add exclusive C14N transform */
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
cleanup:
	lasso_release(uri);
	return rc;
}

static gint
create_signature_context(LassoServer *server, xmlSecDSigCtx **ctx_ptr) {
	xmlSecDSigCtx *dsig_ctx = NULL;
	gint rc = 0;

	lasso_bad_param(SERVER, server);
	lasso_null_param(ctx_ptr);

	/* Allocate an initialize the object */
	dsig_ctx = xmlSecDSigCtxCreate(NULL);
	/* Load the private key for the server object */
	/* XXX: handle other formats */
	/* XXX: handle password protected keys */
	/* XXX: handle pkcs12 all-in-one files */
	dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(server->private_key,
			xmlSecKeyDataFormatPem,
			NULL, NULL, NULL);
	goto_cleanup_if_fail_with_rc(dsig_ctx->signKey != NULL, LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED);
	/* Load the certificate chain if needed */
	if (server->certificate) {
		gint ret = xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey,
			server->certificate,
			xmlSecKeyDataFormatPem);
		goto_cleanup_if_fail_with_rc(ret >= 0, LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED);
	}
	/* Transfer the reference */
	*ctx_ptr = dsig_ctx;
	dsig_ctx = NULL;
cleanup:
	if (dsig_ctx) {
		xmlSecDSigCtxDestroy(dsig_ctx);
	}
	return rc;

}

static xmlChar *
make_id_ref(xmlChar *id) {
	char *res = NULL;

	res = g_strdup_printf("#%s", (char*)id);
	return (xmlChar*)res;
}

static void
add_key_info_security_token_reference(xmlDocPtr doc, xmlNode *signature, xmlChar *assertion_id) {
	xmlNsPtr nsPtr = NULL;
	xmlChar *value = NULL;
	xmlNode *key_info = NULL, *security_token_reference = NULL, *reference = NULL;

	/* Add key info */
	key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
	/* Free children */
	xmlFreeNodeList(key_info->children);
	key_info->children = NULL;
	/* Create sec:SecurityTokenReferenceNode */
	security_token_reference = xmlSecAddChild(key_info, (xmlChar*) "SecurityTokenReference",
		(xmlChar*)LASSO_WSSE1_HREF);
	nsPtr = xmlSearchNsByHref(doc, security_token_reference, (xmlChar*) LASSO_SEC_HREF);
	if (nsPtr == NULL) {
		nsPtr = xmlNewNs(security_token_reference, (xmlChar*) LASSO_SEC_HREF,
			(xmlChar*) LASSO_SEC_PREFIX);
	}
	value = (xmlChar*) g_strdup_printf("%s:MessageAuthentication", nsPtr->prefix);
	xmlSetProp(security_token_reference, (xmlChar*) "Usage", value);
	lasso_release(value);
	/* Create Reference */
	reference = xmlSecAddChild(security_token_reference, (xmlChar*) "Reference",
		(xmlChar*) LASSO_WSSE1_HREF);
	value = make_id_ref(assertion_id);
	xmlSetProp(reference, (xmlChar*) "URI", value);
	lasso_release(value);
}

/**
 * lasso_wsf_profile_add_saml_signature:
 * @wsf_profile: a #LassoWsfProfile
 * @doc: the #xmlDoc document that contains the SOAP message to sign
 *
 * This function add the signature to comply with specification of the ID-WSF
 * SAML security mechanism.  In order to do that we must sign the headers
 * Provider, Correlation and eventually is:Interaction and also the Body of the
 * SOAP message.
 *
 * Return value: 0 if signature creation succeeded, an error code otherwise.
 */
static gint
lasso_wsf_profile_add_saml_signature(LassoWsfProfile *wsf_profile, xmlDoc *doc) {
	xmlNode *envelope = NULL, *header = NULL, *body = NULL, *provider = NULL, *correlation = NULL;
	xmlNode *interaction = NULL, *security = NULL, *assertion = NULL, *signature = NULL;
	xmlChar *provider_id = NULL, *correlation_id = NULL, *interaction_id = NULL, *body_id = NULL;
	xmlChar *assertion_id = NULL;
	xmlSecDSigCtx *dsig_ctx = NULL;
	const xmlChar* ids[] = {
		(xmlChar*) "id",
		(xmlChar*) "Id",
		NULL
	};
	gint rc = 0, sec_ret = 0;


	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(wsf_profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(doc != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* Lookup all referenced node and their Ids */
	envelope = xmlDocGetRootElement(doc);
	header = xmlSecSoap11GetHeader(envelope);

	provider = xmlSecFindNode(header, (xmlChar*) "Provider",
		(xmlChar*) LASSO_SOAP_BINDING_HREF);
	correlation = xmlSecFindNode(header, (xmlChar*) "Correlation",
		(xmlChar*) LASSO_SOAP_BINDING_HREF);
	interaction = xmlSecFindNode(header, (xmlChar*) "UserInteraction",
		(xmlChar*) LASSO_IS_HREF);
	body = xmlSecSoap11GetBody(envelope);
	xmlSecAddIDs(doc, envelope, ids);
	goto_cleanup_if_fail_with_rc(header != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);
	goto_cleanup_if_fail_with_rc(provider != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);
	goto_cleanup_if_fail_with_rc(correlation != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);
	goto_cleanup_if_fail_with_rc(body != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);

	provider_id = xmlGetProp(provider, (xmlChar*) "id");
	correlation_id = xmlGetProp(correlation, (xmlChar*) "id");
	if (interaction != NULL) {
		interaction_id = xmlGetProp(interaction, (xmlChar*) "id");
	}
	body_id = xmlGetProp(body, (xmlChar*) "Id");
	goto_cleanup_if_fail_with_rc(provider_id != NULL, LASSO_XML_ERROR_ATTR_NOT_FOUND);
	goto_cleanup_if_fail_with_rc(correlation_id != NULL, LASSO_XML_ERROR_ATTR_NOT_FOUND);
	goto_cleanup_if_fail_with_rc(body_id != NULL, LASSO_XML_ERROR_ATTR_NOT_FOUND);
	goto_cleanup_if_fail_with_rc(interaction == NULL || interaction_id != NULL,
		LASSO_XML_ERROR_ATTR_NOT_FOUND);

	/* Lookup the assertion Id for the KeyInfo node generation */
	security = xmlSecFindNode(header, (xmlChar*) "Security", (xmlChar*) LASSO_WSSE1_HREF);
	goto_cleanup_if_fail_with_rc(security != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);
	assertion = xmlSecFindNode(security, (xmlChar*) "Assertion", (xmlChar*) LASSO_SAML_ASSERTION_HREF);
	goto_cleanup_if_fail_with_rc(assertion != NULL, LASSO_XML_ERROR_NODE_NOT_FOUND);
	assertion_id = xmlGetProp(assertion, (xmlChar*)"AssertionID");
	goto_cleanup_if_fail_with_rc(assertion_id != NULL, LASSO_XML_ERROR_ATTR_NOT_FOUND);

	/* Create the signature template */
	rc = add_signature_template(wsf_profile->server, doc, security, &signature);
	if (rc != 0) {
		goto cleanup;
	}
	rc = add_reference_to_non_enveloping_id(signature, provider_id);
	if (rc != 0) {
		goto cleanup;
	}
	rc = add_reference_to_non_enveloping_id(signature, correlation_id);
	if (rc != 0) {
		goto cleanup;
	}
	rc = add_reference_to_non_enveloping_id(signature, body_id);
	if (rc != 0) {
		goto cleanup;
	}
	if (interaction_id) {
		rc = add_reference_to_non_enveloping_id(signature, interaction_id);
		if (rc != 0) {
			goto cleanup;
		}
	}
	/* Create signature context */
	xmlSetTreeDoc(envelope, doc);
	rc = create_signature_context(wsf_profile->server, &dsig_ctx);
	if (rc != 0)
		goto cleanup;
	/* Sign ! */
	sec_ret = xmlSecDSigCtxSign(dsig_ctx, signature);
	if (sec_ret < 0) {
		rc = LASSO_DS_ERROR_SIGNATURE_FAILED;
		goto cleanup;
	}
	add_key_info_security_token_reference(doc, signature, assertion_id);

cleanup:
	if (dsig_ctx) {
		xmlSecDSigCtxDestroy(dsig_ctx);
	}
	lasso_release_xml_string(provider_id);
	lasso_release_xml_string(correlation_id);
	lasso_release_xml_string(interaction_id);
	lasso_release_xml_string(body_id);
	lasso_release_xml_string(assertion_id);
	return rc;
}

/**
 * lasso_wsf_profile_get_remote_provider_id:
 * @wsf_profile: a #LassoWsfProfile object
 *
 * Return the remote provider id parsed in the last processing of a SOAP request or a SOAP response.
 *
 * Return value:(transfer none)(allow-none): the provider id string or NULL.
 */
const char*
lasso_wsf_profile_get_remote_provider_id(LassoWsfProfile *wsf_profile)
{
	lasso_return_val_if_invalid_param(WSF_PROFILE, wsf_profile, NULL);

	return wsf_profile->private_data->remote_provider_id;
}

/**
 * lasso_wsf_profile_get_remote_provider:
 * @wsf_profile: a #LassoWsfProfile object
 * @provider:(transfer full): an output pointer to #LassoProvider object variable.
 *
 * Return the remote provider parsed in the last processing of a SOAP request or a SOAP response.
 *
 * Return value: 0 if successfull, LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID if no provider id
 * is present in the SOAP headers, or LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND if the provider is
 * unknown to us.
 */
gint
lasso_wsf_profile_get_remote_provider(LassoWsfProfile *wsf_profile, LassoProvider **provider)
{
	LassoProvider *_provider = NULL;

	lasso_bad_param(WSF_PROFILE, wsf_profile);

	if (! wsf_profile->private_data->remote_provider_id)
		return LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID;

	if (! LASSO_IS_SERVER(wsf_profile->server))
		return LASSO_PROFILE_ERROR_MISSING_SERVER;

	_provider = lasso_server_get_provider(wsf_profile->server, wsf_profile->private_data->remote_provider_id);
	if (! _provider)
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;

	if (provider) {
		lasso_assign_gobject(*provider, _provider);
	}
	return 0;
}

/**
 * lasso_wsf_profile_get_fault:
 * @wsf_profile: a #LassoWsfProfile object
 *
 * If a fault is going to be returned as next response, return it.
 *
 * Return value:(transfer none)(allow-none): a #LassoSoapFault, or NULL if none is currently present in the object.
 */
LassoSoapFault*
lasso_wsf_profile_get_soap_fault(LassoWsfProfile *wsf_profile)
{
	lasso_return_val_if_invalid_param(WSF_PROFILE, wsf_profile, NULL);

	if (wsf_profile->private_data)
		return wsf_profile->private_data->soap_fault;
	return NULL;
}

/**
 * lasso_wsf_profile_set_soap_fault:
 * @wsf_profile: a #LassoWsfProfile object
 * @soap_fault: a #LassoSoapFault object
 *
 * Set a SOAP fault to be returned in next SOAP response message. The SOAP fault is removed by
 * lasso_wsf_profile_init_soap_request.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_wsf_profile_set_soap_fault(LassoWsfProfile *wsf_profile, LassoSoapFault *soap_fault)
{
	lasso_bad_param(WSF_PROFILE, wsf_profile);
	if (! LASSO_IS_SOAP_FAULT(soap_fault) && soap_fault)
		return LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ;
	if (! wsf_profile->private_data)
		return LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT;
	lasso_assign_gobject(wsf_profile->private_data->soap_fault, soap_fault);
	return 0;
}

/**
 * lasso_wsf_profile_set_status_code:
 * @wsf_profile: a #LassoWsfProfile
 * @status_code: a string representing the status code
 *
 * Set the status code to set in the next built response.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_wsf_profile_set_status_code(LassoWsfProfile *wsf_profile, const char *status_code)
{
	lasso_bad_param(WSF_PROFILE, wsf_profile);
	if (! wsf_profile->private_data)
		return LASSO_PARAM_ERROR_NON_INITIALIZED_OBJECT;
	lasso_assign_string(wsf_profile->private_data->status_code, status_code);
	return 0;
}

/**
 * lasso_wsf_profile_get_status_code:
 * @wsf_profile: a #LassoWsfProfile object
 *
 * Return the actual status code for this protocol object.
 *
 * Return value:(transfer none)(allow-none): a string owned by the profile object or NULL.
 */
const char*
lasso_wsf_profile_get_status_code(LassoWsfProfile *wsf_profile) {
	lasso_return_val_if_invalid_param(WSF_PROFILE, wsf_profile, NULL);

	if (wsf_profile->private_data)
		return wsf_profile->private_data->status_code;
	return NULL;
}
