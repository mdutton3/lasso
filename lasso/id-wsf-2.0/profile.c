/* $Id: wsf_profile.c,v 1.45 2007/01/05 16:11:02 Exp $
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

#include <stdio.h>
#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include "../id-ff/server.h"
#include "../id-ff/serverprivate.h"
#include "../id-ff/providerprivate.h"

#include "../saml-2.0/profileprivate.h"

#include "profile.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "../xml/idwsf_strings.h"
#include "session.h"

#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/soap_binding_correlation.h"
#include "../xml/soap_binding_provider.h"
#include "../xml/soap_binding_processing_context.h"
#include "../xml/xml_enc.h"
#include "../xml/id-wsf-2.0/sb2_sender.h"
#include "../xml/id-wsf-2.0/sb2_redirect_request.h"
#include "../xml/id-wsf-2.0/util_status.h"

#include "../xml/ws/wsse_security_header.h"

#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/misc_text_node.h"
#include "../utils.h"
#include "idwsf2_helper.h"
#include "soap_binding.h"
#include "../id-wsf/wsf_utils.h"
#include "../saml-2.0/saml2_helper.h"

#define LASSO_IDWSF2_PROFILE_ELEMENT_EPR "Epr"
#define LASSO_IDWSF2_PROFILE_ELEMENT_REQUEST "SoapEnvelopeRequest"
#define LASSO_IDWSF2_PROFILE_ELEMENT_RESPONSE "SoapEnvelopeResponse"

/**
 * LassoIdWsf2ProfilePrivate:
 * @epr: the #LassoWsAddrEndpointReference object representing the targetd service
 * @soap_envelope_request: the #LassoSoapEnvelope object for the request message
 * @soap_envelope_response: the #LassoSoapEnvelope object for the response
 */
struct _LassoIdWsf2ProfilePrivate {
	LassoWsAddrEndpointReference *epr;
	LassoSoapEnvelope *soap_envelope_request;
	LassoSoapEnvelope *soap_envelope_response;
};

#define private_accessors(type, name) \
static type \
_get_##name(LassoIdWsf2Profile *idwsf2_profile)\
{ \
	if (idwsf2_profile && idwsf2_profile->private_data) \
	{ \
		return idwsf2_profile->private_data->name; \
	} \
	return 0; \
} \
static void \
_set_##name(LassoIdWsf2Profile *idwsf2_profile, \
		type what) \
{ \
	if (idwsf2_profile && idwsf2_profile->private_data) \
	{ \
		lasso_assign_gobject(idwsf2_profile->private_data->name, what); \
	} \
}

private_accessors(LassoWsAddrEndpointReference*,epr)
private_accessors(LassoSoapEnvelope*,soap_envelope_request)
private_accessors(LassoSoapEnvelope*,soap_envelope_response)


static void
_add_fault_for_rc(LassoIdWsf2Profile *profile, int rc)
{
	LassoSoapFault *fault;
	char *code;

	if (rc) {
		code = g_strdup_printf("LASSO_ERROR_%i", rc);
		fault = lasso_soap_fault_new_full(code, lasso_strerror(rc));
		lasso_release(code);
		lasso_release_list_of_gobjects(_get_soap_envelope_response(profile)->Header->Other);
		lasso_soap_envelope_add_to_body(_get_soap_envelope_response(profile), (LassoNode*)fault);
	}
}

/**
 * lasso_idwsf2_profile_build_soap_envelope:
 * @refToMessageId: (allow-none): the string ID of the request
 * @providerId: (allow-none): the providerID of the sender
 *
 * Build a new SOAP envelope, for transmitting an ID-WSF request of response. If the message is a
 * response, refer to the request whose ID is @refToMessageId.
 *
 * Return value: a new #LassoSoapEnvelope if successful, NULL otherwise.
 */
static LassoSoapEnvelope*
lasso_idwsf2_profile_build_soap_envelope(const char *refToMessageId, const char *providerID)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;
	LassoIdWsf2Sb2Sender *sender;
	LassoWsAddrAttributedURI *message_id;

	/* Body */
	body = lasso_soap_body_new();
	body->Id = lasso_build_unique_id(32);
	envelope = lasso_soap_envelope_new(body);

	/* Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	if (providerID) {
		/* Sender */
		sender = lasso_idwsf2_sb2_sender_new();
		lasso_assign_string(sender->providerID, providerID);
		lasso_list_add_gobject(header->Other, sender);
	}

	message_id = lasso_soap_envelope_get_message_id(envelope, TRUE);
	message_id->content = lasso_build_unique_id(32);

	if (refToMessageId) {
		LassoWsAddrAttributedURI *relates_to;
		relates_to = lasso_wsa_attributed_uri_new_with_string(refToMessageId);
		lasso_node_set_custom_nodename((LassoNode*)relates_to, "RelatesTo");
		lasso_list_add_gobject(header->Other, relates_to);
	}

	return envelope;
}

/**
 * lasso_idwsf2_profile_init_request:
 * @profile: a #LassoIdWsf2Profile object
 *
 * Initialize a new SOAP ID-WSF 2.0 request. Clear the existing request if one is currently set.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_profile_init_request(LassoIdWsf2Profile *idwsf2_profile)
{
	LassoSoapEnvelope *envelope = NULL;
	LassoProfile *profile = NULL;
	LassoWsAddrEndpointReference *epr;
	const char *provider_id = NULL;
	int rc = 0;

	lasso_bad_param(IDWSF2_PROFILE, idwsf2_profile);
	profile = &idwsf2_profile->parent;
	epr = lasso_idwsf2_profile_get_epr(idwsf2_profile);

	if (epr) {
		LassoIdWsf2DiscoSecurityContext *security_context;

		security_context =
			lasso_wsa_endpoint_reference_get_idwsf2_security_context_for_security_mechanism(
				epr, lasso_security_mech_id_is_bearer_authentication, NULL, FALSE);
		if (! security_context) {
			return LASSO_WSF_PROFILE_ERROR_UNSUPPORTED_SECURITY_MECHANISM;
		}
	}

	if (LASSO_IS_SERVER(profile->server)) {
		provider_id = profile->server->parent.ProviderID;
	}
	envelope = lasso_idwsf2_profile_build_soap_envelope(NULL, provider_id);
	_set_soap_envelope_request(idwsf2_profile, envelope);
	lasso_release_gobject(profile->request);

	lasso_release_gobject(envelope);
	return rc;
}

/**
 * lasso_idwsf2_profile_init_response:
 * @profile: a #LassoIdWsf2Profile object
 *
 * Initialize a new SOAP ID-WSF 2.0 response. Clear the existing response if one is currently set.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_profile_init_response(LassoIdWsf2Profile *profile)
{
	char *provider_id = NULL;
	LassoSoapEnvelope *soap_envelope;
	int rc = 0;
	LassoWsAddrAttributedURI *request_message_id;
	char *request_message_id_content = NULL;

	lasso_bad_param(IDWSF2_PROFILE, profile);

	if (LASSO_IS_SERVER(profile->parent.server)) {
		provider_id = profile->parent.server->parent.ProviderID;
	}
	request_message_id = lasso_soap_envelope_get_message_id(
			lasso_idwsf2_profile_get_soap_envelope_request(profile), FALSE);
	if (request_message_id) {
		request_message_id_content = request_message_id->content;
	}
	soap_envelope = lasso_idwsf2_profile_build_soap_envelope(request_message_id_content, provider_id);
	_set_soap_envelope_response(profile, soap_envelope);
	lasso_release_gobject(profile->parent.response);

	return rc;
}

/**
 * lasso_idwsf2_profile_build_request_msg:
 * @profile: a #LassoIdWsf2Profile object
 *
 * Serialize and sign, if needed, the SOAP request message, put the result in
 * <programlisting>LASSO_PROFILE(profile)->msg_body</programlisting>.
 *
 * FIXME: really do sign messages.
 *
 * Return value: 0 if successful, LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED.
 */
gint
lasso_idwsf2_profile_build_request_msg(LassoIdWsf2Profile *profile, const char *security_mech_id)
{
	LassoWsAddrEndpointReference *epr;
	LassoSoapEnvelope *envelope;
	int rc = 0;

	lasso_bad_param(IDWSF2_PROFILE, profile);
	epr = lasso_idwsf2_profile_get_epr(profile);
	envelope = _get_soap_envelope_request(profile);

	/* Handle SOAP Binding and WS-Security, when given an EPR */
	if (LASSO_IS_WSA_ENDPOINT_REFERENCE(epr)) {
		if (epr->Address != NULL) {
			lasso_assign_string(profile->parent.msg_url, epr->Address->content);
		}

		/* Default try bearer */
		if (security_mech_id == NULL || lasso_security_mech_id_is_bearer_authentication(
					security_mech_id)) {
			LassoNode *security_token;

			security_token = lasso_wsa_endpoint_reference_get_security_token(epr,
					lasso_security_mech_id_is_bearer_authentication, NULL);
			if (security_token) {
				xmlNode *real_thing;

				real_thing = lasso_node_get_original_xmlnode(security_token);
				if (! real_thing) {
					message(G_LOG_LEVEL_CRITICAL, "Cannot put the unaltered security token in the header");
					goto_cleanup_with_rc(LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED);
				} else {
					LassoMiscTextNode *misc;

					misc = lasso_misc_text_node_new_with_xml_node(real_thing);
					lasso_soap_envelope_add_security_token (envelope, (LassoNode*)misc);
					lasso_release_gobject(misc);
				}
			} else {
				message(G_LOG_LEVEL_WARNING, "No security mechanism specified, " \
						"failed to find security token for Bearer mechanism");
			}
			if (lasso_wsa_endpoint_reference_get_target_identity_token(epr,
					lasso_security_mech_id_is_bearer_authentication, NULL) != NULL) {
				message(G_LOG_LEVEL_CRITICAL, "TargetIdentity token are not supported");
			}
		} else {
			message(G_LOG_LEVEL_CRITICAL, "Only Bearer security mechanism is supported by ID-WSF 2.0 module of Lasso");
		}
	}

	LASSO_PROFILE(profile)->msg_body = lasso_node_export_to_xml(
			LASSO_NODE(_get_soap_envelope_request(profile)));

	if (! LASSO_PROFILE(profile)->msg_body)
		return LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED;

cleanup:
	return rc;
}

/**
 * lasso_idwsf2_profile_process_request_msg:
 * @wsf2_profile: a #LassoIdWsf2Profile object
 * @message: a received SOAP message
 *
 * Parse a SOAP request message and initialize the SOAP Envelope for the response.
 *
 * Return value: 0 if successful, an error code otherwise among:
 * <itemizedlist>
 * <listitem><para>LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if @profile is not a #LassoIdWsf2Profile
 * object,</para></listitem>
 * <listitem><para>LASSO_PARAM_ERROR_INVALID_VALUE if message is NULL,</para></listitem>
 * <listitem><para>LASSO_PROFILE_ERROR_INVALID_MSG if we cannot parse the message,</para></listitem>
 * <listitem><para>LASSO_SOAP_ERROR_MISSING_BODY if the message has no body
 * content.</para></listitem>
 * </itemizedlist>
 */
gint
lasso_idwsf2_profile_process_request_msg(LassoIdWsf2Profile *wsf2_profile, const gchar *message)
{
	LassoProfile *profile = NULL;
	LassoSoapEnvelope *envelope = NULL;
	LassoWsAddrAttributedURI *message_id;
	char *message_id_content = NULL;
	char *provider_id;
	int rc = 0;

	lasso_bad_param(IDWSF2_PROFILE, wsf2_profile);
	lasso_check_non_empty_string(message);

	/* Clean some fields */
	lasso_release_gobject(wsf2_profile->parent.nameIdentifier);
	lasso_release_string(wsf2_profile->parent.remote_providerID);
	lasso_release_string(wsf2_profile->parent.msg_body);
	lasso_release_gobject(wsf2_profile->private_data->soap_envelope_response);
	lasso_release_gobject(wsf2_profile->parent.response);

	/* Get soap request */
	profile = LASSO_PROFILE(wsf2_profile);
	
	lasso_assign_new_gobject(wsf2_profile->private_data->soap_envelope_request,
			lasso_soap_envelope_new_from_message(message));
	if (! LASSO_IS_SOAP_ENVELOPE(_get_soap_envelope_request(wsf2_profile))) {
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}
	envelope = _get_soap_envelope_request(wsf2_profile);
	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL &&
			LASSO_IS_NODE(envelope->Body->any->data)) {
		lasso_assign_gobject(profile->request, envelope->Body->any->data);
	} else {
		rc = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	/* Initialize soap response */
	message_id = lasso_soap_envelope_get_message_id(
			_get_soap_envelope_request(wsf2_profile), FALSE);
	if (message_id) {
		message_id_content = message_id->content;
	}
	if (LASSO_IS_SERVER(profile->server)) {
		provider_id = profile->server->parent.ProviderID;
		lasso_assign_new_gobject(wsf2_profile->private_data->soap_envelope_response,
				lasso_idwsf2_profile_build_soap_envelope(message_id_content, provider_id));
	}
	_add_fault_for_rc(wsf2_profile, rc);

cleanup:
	return rc;
}

/**
 * lasso_idwsf2_profile_check_security_mechanism:
 * @profile: a #LassoIdWsf2Profile object
 * @security_mech_id:(allow-none): the security mechanism to enforce, if none is provided Bearer is
 * assumed.
 *
 * Check ID-WSF 2.0 Security Mechanism upon the received request. It is mandatory that a
 * #LassoServer is setted for the @profile object.
 *
 * Return value: 0 if the request passed the check, an error code otherwise.
 */
gint
lasso_idwsf2_profile_check_security_mechanism(LassoIdWsf2Profile *profile,
		const char *security_mech_id)
{
	LassoSoapEnvelope *envelope = NULL;
	int rc = LASSO_WSF_PROFILE_ERROR_SECURITY_MECHANISM_CHECK_FAILED;

	if (! LASSO_IS_SERVER(profile->parent.server))
		return LASSO_PROFILE_ERROR_MISSING_SERVER;

	lasso_bad_param(IDWSF2_PROFILE, profile);
	envelope = _get_soap_envelope_request(profile);
	/* Verify security mechanism */
	if (security_mech_id == NULL ||
			lasso_security_mech_id_is_bearer_authentication(security_mech_id) || lasso_security_mech_id_is_saml_authentication(security_mech_id)) {
		LassoSaml2Assertion *assertion;
		LassoProvider *issuer;
		const char *sender_id = NULL, *local_service_id = NULL;
		const char *name_qualifier = NULL, *sp_name_qualifier = NULL;
		LassoSaml2AssertionValidationState validation_state;
		LassoProviderRole role;

		assertion = lasso_soap_envelope_get_saml2_security_token (envelope);
		if (assertion == NULL)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_ASSERTION);
		validation_state = lasso_saml2_assertion_validate_conditions(assertion, NULL);
		if (validation_state != LASSO_SAML2_ASSERTION_VALID)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_ASSERTION_CONDITIONS);
		issuer = lasso_saml2_assertion_get_issuer_provider(assertion, profile->parent.server);
		if (! issuer)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_UNKNOWN_ISSUER);
		if (issuer == &profile->parent.server->parent || issuer->role == 0) {
			role = issuer->private_data->roles;
		} else {
			role = issuer->role;
		}
		if ((role & LASSO_PROVIDER_ROLE_IDP) == 0)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_ISSUER_IS_NOT_AN_IDP);
		lasso_check_good_rc(lasso_provider_verify_single_node_signature(issuer,
					(LassoNode*)assertion, "ID"));
		lasso_check_good_rc(lasso_saml2_assertion_decrypt_subject(assertion,
					profile->parent.server));
		if (assertion && assertion->Subject && assertion->Subject->NameID) {
			name_qualifier = assertion->Subject->NameID->NameQualifier;
			sp_name_qualifier = assertion->Subject->NameID->SPNameQualifier;
		}
		if (! name_qualifier || lasso_strisnotequal(name_qualifier,issuer->ProviderID))
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_ASSERTION);
		/* There is two cases for the NameID of the security assertion:
		 * - we are the IdP and the Wsp, so the NameQualifier is us and the SPNameQualifier is the
		 *   Sender
		 * - we are a simple Wsp, so the NameQualifier is an IdP we know and the
		 *   SPNameQualifier is us.
		 */
		if (! profile->parent.server)
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_MISSING_SERVER);
		local_service_id = profile->parent.server->parent.ProviderID;
		sender_id = lasso_soap_envelope_sb2_get_provider_id(envelope);
		if (! sender_id)
			goto_cleanup_with_rc(LASSO_WSF_PROFILE_ERROR_MISSING_SENDER_ID);
		if (local_service_id && lasso_strisequal(local_service_id,name_qualifier) &&
				sp_name_qualifier && lasso_strisequal(sp_name_qualifier,sender_id)) {
			/* Ok. */
		} else if (sp_name_qualifier && lasso_strisequal(sp_name_qualifier,local_service_id)) {
			/* Ok. */
		} else {
			goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_ASSERTION);
		}
	}

	if (security_mech_id != NULL && ! lasso_security_mech_id_is_bearer_authentication(security_mech_id)) {
		message(G_LOG_LEVEL_WARNING, "Only Bearer mechanism is supported!");
		goto_cleanup_with_rc(LASSO_ERROR_UNIMPLEMENTED);
	}
	rc = 0;
cleanup:
	_add_fault_for_rc(profile, rc);
	return rc;
}

/**
 * lasso_idwsf2_profile_init_soap_fault_response:
 * @profile: a #LassoIdWsf2Profile object
 * @faultcode: a SOAP fault code, see #LASSO_SOAP_FAULT_CLIENT, #LASSO_SOAP_FAULT_SERVER.
 * @faultstring:(allow-none): a human description of the error
 * @details:(allow-none)(element-type LassoNode): complementary data describing the error, you can use
 * #LassoIdWsf2UtilStatus.
 *
 * Initialize a new SOAP 1.1 fault.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_profile_init_soap_fault_response(LassoIdWsf2Profile *profile, const char *faultcode,
		const char *faultstring, GList *details)
{
	int rc = 0;
	LassoSoapEnvelope *envelope;

	lasso_check_good_rc(lasso_idwsf2_profile_init_response(profile));
	lasso_check_good_rc(lasso_profile_set_soap_fault_response(&profile->parent, faultcode,
				faultstring, details));
	envelope = lasso_idwsf2_profile_get_soap_envelope_response(profile);
	if (envelope) {
		lasso_list_add_gobject(envelope->Body->any, profile->parent.response);
	}
cleanup:
	return rc;
}

/**
 * lasso_idwsf2_profile_redirect_user_for_interaction:
 * @profile: a #LassoIdWsf2Profile object
 * @redirect_url: an URL where the user must be redirected
 *
 * Create a SOAP fault containing a RedirectRequest element, with a redirectURL property set to
 * @redirect_url concatenated with the parameter "transactionID" set to the messageID of the
 * response message.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
gint
lasso_idwsf2_profile_redirect_user_for_interaction(
	LassoIdWsf2Profile *profile, const gchar *redirect_url, gboolean for_data)
{
	LassoSoapFault *fault = NULL;
	char *url = NULL;
	LassoIdWsf2Sb2RedirectRequest *redirect_request = NULL;
	LassoIdWsf2Sb2UserInteractionHint hint;
	LassoIdWsf2Sb2UserInteractionHeader *user_interaction_header;
	LassoSoapEnvelope *soap_envelope_request;
	LassoWsAddrAttributedURI *messageID;
	int rc = 0;

	lasso_bad_param(IDWSF2_PROFILE, profile);
	lasso_check_non_empty_string(redirect_url);

	soap_envelope_request = lasso_idwsf2_profile_get_soap_envelope_request(profile);
	if (! soap_envelope_request) {
		return LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}
	hint = lasso_soap_envelope_get_sb2_user_interaction_hint(soap_envelope_request);
	switch (hint) {
		case LASSO_IDWSF2_SB2_USER_INTERACTION_HINT_DO_NOT_INTERACT:
			goto_cleanup_with_rc(LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED);
		case LASSO_IDWSF2_SB2_USER_INTERACTION_HINT_DO_NOT_INTERACT_FOR_DATA:
			if (for_data) {
				goto_cleanup_with_rc(LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED_FOR_DATA);
			}
		default:
			break;
	}
	user_interaction_header =
		lasso_soap_envelope_get_sb2_user_interaction_header(soap_envelope_request, FALSE);
	if (user_interaction_header == FALSE) {
		goto_cleanup_with_rc(LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST_UNSUPPORTED_BY_REQUESTER);
	}

	messageID = lasso_soap_envelope_get_message_id(_get_soap_envelope_response(profile), FALSE);
	if (! messageID || ! messageID->content) {
		goto_cleanup_with_rc(
				LASSO_WSF_PROFILE_ERROR_INVALID_OR_MISSING_REFERENCE_TO_MESSAGE_ID);
	}
	if (strchr(redirect_url, '?')) {
		url = g_strconcat(redirect_url, "&transactionID=", messageID->content, NULL);
	} else {
		url = g_strconcat(redirect_url, "?transactionID=", messageID->content, NULL);
	}
	redirect_request = lasso_idwsf2_sb2_redirect_request_new_full(url);
	lasso_release(url);
	lasso_check_good_rc(lasso_idwsf2_profile_init_soap_fault_response(profile,
				LASSO_SOAP_FAULT_CODE_SERVER, "Server Error", &(GList){ .data =
				redirect_request, .next = NULL, .prev = NULL } ));

cleanup:
	if (rc) {
		LassoIdWsf2UtilStatus *status;
		const char *status_code = NULL;
		fault = (LassoSoapFault*)profile->parent.response;
		lasso_assign_string(fault->faultcode, LASSO_SOAP_FAULT_CODE_SERVER);
		switch (rc) {
			case LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED:
				status_code = LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_REQUIRED;
				break;
			case LASSO_WSF_PROFILE_ERROR_SERVER_INTERACTION_REQUIRED_FOR_DATA:
				status_code = LASSO_IDWSF2_SB2_STATUS_CODE_SERVER_INTERACTION_REQUIRED;
				break;
			case LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST_UNSUPPORTED_BY_REQUESTER:
				status_code = "RedirectRequestNeeded";
				break;
			default:
				status_code = "UnknownInteraction error";
				break;
		}
		if (status_code) {
			status = lasso_idwsf2_util_status_new_with_code(status_code, NULL);
			lasso_idwsf2_profile_init_soap_fault_response(profile,
					LASSO_SOAP_FAULT_CODE_SERVER, NULL, 
					&(GList){ .data = status, .next = NULL, .prev = NULL});
		} else {
			lasso_idwsf2_profile_init_soap_fault_response(profile,
					LASSO_SOAP_FAULT_CODE_SERVER, NULL, NULL);
		}

	}
	lasso_release_gobject(redirect_request);
	return rc;
}
/**
 * lasso_idwsf2_profile_build_response_msg:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Serialize and sign the SOAP, if needed, the response message, put the result in
 * <programlisting>LASSO_PROFILE(profile)->msg_body</programlisting>.
 *
 * Return value: 0 if successful, LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED otherwise.
 */
gint
lasso_idwsf2_profile_build_response_msg(LassoIdWsf2Profile *idwsf2_profile)
{
	LassoSoapEnvelope *envelope;

	lasso_bad_param(IDWSF2_PROFILE, idwsf2_profile);

	envelope = lasso_idwsf2_profile_get_soap_envelope_response(idwsf2_profile);
	if (envelope == NULL) {
		return LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}
	idwsf2_profile->parent.msg_body = lasso_node_export_to_xml((LassoNode*)envelope);

	if (! LASSO_PROFILE(idwsf2_profile)->msg_body) {
		return LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED;
	}
	return 0;
}

/**
 * lasso_idwsf2_profile_process_response_msg:
 * @profile: a #LassoIdWsf2Profile object
 * @message: a string containing a response message
 *
 * Parse a response received by SOAP. Place the parsed message in the #LassoIdWsf2Profile structure
 * in the @soap_envelope_response field and the content of the body in the @response field.
 *
 * Return value: 0 if successful, one of those error codes if the call fails:
 * <itemizedlist>
 * <listitem><para>LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if first parameter is not
 * a #LassoIdWsf2Profile object,</para></listitem>
 * <listitem><para>LASSO_PARAM_ERROR_INVALID_VALUE if message is NULL,</para></listitem>
 * <listitem><para>LASSO_SOAP_ERROR_MISSING_BODY if no body element is found,</para></listitem>
 * <listitem><para>LASSO_PROFILE_ERROR_MISSING_RESPONSE if the body element is
 * empty.</para></listitem>
 * </itemizedlist>
 */
gint
lasso_idwsf2_profile_process_response_msg(LassoIdWsf2Profile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	int rc = 0;

	lasso_bad_param(IDWSF2_PROFILE, profile);
	lasso_check_non_empty_string(message);

	envelope = lasso_soap_envelope_new_from_message(message);
	_set_soap_envelope_response(profile, envelope);

	goto_cleanup_if_fail_with_rc (envelope != NULL,
			LASSO_PROFILE_ERROR_INVALID_RESPONSE);
	goto_cleanup_if_fail_with_rc (envelope->Body != NULL,
			LASSO_SOAP_ERROR_MISSING_BODY);
	goto_cleanup_if_fail_with_rc (envelope->Body->any != NULL &&
			LASSO_IS_NODE(envelope->Body->any->data),
			LASSO_PROFILE_ERROR_MISSING_RESPONSE);

	lasso_assign_gobject(profile->parent.response,
			envelope->Body->any->data);

	if (LASSO_IS_SOAP_FAULT(profile->parent.response)) {
		LassoSoapFault *fault = (LassoSoapFault*)profile->parent.response;
		if (LASSO_IS_SOAP_DETAIL(fault->Detail)) {
			LassoIdWsf2Sb2RedirectRequest *redirect_request;
			redirect_request =
				lasso_extract_gobject_from_list(
						LassoIdWsf2Sb2RedirectRequest,
						LASSO_TYPE_IDWSF2_SB2_REDIRECT_REQUEST,
						fault->Detail->any);
			if (redirect_request) {
				lasso_assign_string(profile->parent.msg_url, redirect_request->redirectURL);
				return LASSO_WSF_PROFILE_ERROR_REDIRECT_REQUEST;
			}
			return LASSO_WSF_PROFILE_ERROR_SOAP_FAULT;

		}
	}

cleanup:
	return rc;
}

/**
 * lasso_idwsf2_profile_get_soap_envelope_request:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Return the last parsed SOAP request object.
 *
 * Return value:(transfer none): a #LassoSoapEnvelope object or NULL if no request as ever been
 * parsed with this object. You must free this object.
 */
LassoSoapEnvelope*
lasso_idwsf2_profile_get_soap_envelope_request(LassoIdWsf2Profile *idwsf2_profile)
{
	return _get_soap_envelope_request(idwsf2_profile);

}

/**
 * lasso_idwsf2_profile_get_soap_envelope_response:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Return the last parsed SOAP response object.
 *
 * Return value:(transfer none): a #LassoSoapEnvelope object or NULL if no response as ever been
 * parsed with this objects. You must free this object.
 */
LassoSoapEnvelope*
lasso_idwsf2_profile_get_soap_envelope_response(LassoIdWsf2Profile *idwsf2_profile)
{
	return _get_soap_envelope_response(idwsf2_profile);

}

/**
 * lasso_idwsf2_profile_get_name_identifier:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Return the NameIdentifier found in a WS-Security authentication token, when Bearer or SAML
 * security mechanism is used. This method does not validate any security conditions on the
 * assertion.
 *
 * Return value:(transfer full)(allow-none): a #LassoNode object or NULL.
 */
LassoNode *
lasso_idwsf2_profile_get_name_identifier(LassoIdWsf2Profile *idwsf2_profile)
{
	LassoSaml2Assertion *assertion = NULL;
	LassoSaml2NameID *nameID = NULL;
	LassoIdWsf2Sb2TargetIdentity *target_identity = NULL;
	LassoSaml2EncryptedElement *encryptedID = NULL;

	if (! LASSO_IS_IDWSF2_PROFILE(idwsf2_profile))
		return NULL;

	/** Already extracted, return it */
	if (idwsf2_profile->parent.nameIdentifier != NULL)
		goto cleanup;

	/* Try to get a SAML2 assertion */
	assertion = lasso_soap_envelope_get_saml2_security_token
		(lasso_idwsf2_profile_get_soap_envelope_request(idwsf2_profile));
	if (assertion && assertion->Subject) {

		if (lasso_saml2_assertion_decrypt_subject(assertion,
					idwsf2_profile->parent.server) != 0) {
			goto cleanup;
		}

		lasso_assign_gobject (nameID, assertion->Subject->NameID);
	}
	/* We found nothing */
	if (!nameID && !encryptedID) {
		GList *it;
		/* Go look at the target identity */
		target_identity = lasso_soap_envelope_sb2_get_target_identity_header (
				lasso_idwsf2_profile_get_soap_envelope_request (idwsf2_profile));
		if (target_identity) {
			lasso_foreach (it, target_identity->any)
			{
				if (LASSO_IS_SAML2_NAME_ID(it->data)) {
					lasso_assign_gobject (nameID, it->data);
					break;
				}
				if (LASSO_IS_SAML2_ENCRYPTED_ELEMENT(it->data)) {
					lasso_assign_gobject (encryptedID, it->data);
					break;
				}
			}
		}
	}

	if (!nameID && encryptedID) {
		/* We need a server object to check for audience and decrypt encrypted NameIDs */
		if (! LASSO_IS_SERVER(idwsf2_profile->parent.server)) {
			goto cleanup;
		}
		if (lasso_saml20_profile_process_name_identifier_decryption(&idwsf2_profile->parent, &nameID,
					&encryptedID) != 0) {
			message(G_LOG_LEVEL_WARNING, "process_name_identifier_decryption failed "\
					"when retrieving name identifier for ID-WSF profile");
		}
	}

cleanup:
	lasso_release_gobject (assertion);
	lasso_release_gobject (encryptedID);
	lasso_assign_gobject (idwsf2_profile->parent.nameIdentifier, nameID);
	return (LassoNode*)nameID;
}

/**
 * lasso_idwsf2_profile_get_epr:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 * @epr: a #LassoWsAddrEndpointReference object
 *
 * Set the EPR for the service targeted by the profile object.
 *
 */
void
lasso_idwsf2_profile_set_epr(LassoIdWsf2Profile *idwsf2_profile,
		LassoWsAddrEndpointReference *epr)
{
	if (! LASSO_IS_IDWSF2_PROFILE(idwsf2_profile) || ! LASSO_IS_WSA_ENDPOINT_REFERENCE(epr) ||
			! idwsf2_profile->private_data)
		return;
	_set_epr(idwsf2_profile, epr);
}

/**
 * lasso_idwsf2_profile_get_epr:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Return the EPR used by this profile.
 *
 * Return value:(transfer none): a #LassoWsAddrEndpointReference object, or NULL if none is set.
 */
LassoWsAddrEndpointReference*
lasso_idwsf2_profile_get_epr(LassoIdWsf2Profile *idwsf2_profile)
{
	if (! LASSO_IS_IDWSF2_PROFILE(idwsf2_profile) || ! idwsf2_profile->private_data)
		return NULL;
	return _get_epr(idwsf2_profile);
}


static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoIdWsf2Profile *profile = LASSO_IDWSF2_PROFILE(object);

	if (profile->private_data) {
		lasso_release_gobject(profile->private_data->soap_envelope_request);
		lasso_release_gobject(profile->private_data->soap_envelope_response);
	}
	lasso_release(profile->private_data);

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
instance_init(LassoIdWsf2Profile *discovery)
{
	discovery->private_data = g_new0(LassoIdWsf2ProfilePrivate, 1);
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	LassoProfile *profile = LASSO_PROFILE(node);
	LassoIdWsf2Profile *wsf2_profile = (LassoIdWsf2Profile*)profile;

	if (! LASSO_IS_IDWSF2_PROFILE(profile))
		return NULL;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);

	if (xmlnode && wsf2_profile->private_data) {
		LassoIdWsf2ProfilePrivate *pdata = wsf2_profile->private_data;
		if (pdata->epr) {
			xmlNode *epr;
			epr = xmlNewChild(xmlnode, NULL, BAD_CAST LASSO_IDWSF2_PROFILE_ELEMENT_EPR,
					NULL);
			xmlAddChild(epr, lasso_node_get_xmlNode((LassoNode*) pdata->epr,
						lasso_dump));
		}
		if (pdata->soap_envelope_request) {
			xmlNode *request;
			request = xmlNewChild(xmlnode, NULL, BAD_CAST
					LASSO_IDWSF2_PROFILE_ELEMENT_REQUEST, NULL);
			xmlAddChild(request,
					lasso_node_get_xmlNode(
						(LassoNode*)pdata->soap_envelope_request,
						lasso_dump));
		}
		if (pdata->soap_envelope_response) {
			xmlNode *response;
			response = xmlNewChild(xmlnode, NULL, BAD_CAST
					LASSO_IDWSF2_PROFILE_ELEMENT_RESPONSE, NULL);
			xmlAddChild(response, lasso_node_get_xmlNode((LassoNode*)
						pdata->soap_envelope_response, lasso_dump));
		}
	}

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoIdWsf2Profile *wsf2_profile = (LassoIdWsf2Profile*)node;
	xmlNode *epr_node, *request_node, *response_node;
	LassoWsAddrEndpointReference *epr = NULL;
	LassoSoapEnvelope *request = NULL, *response = NULL;

	if (! LASSO_IS_IDWSF2_PROFILE(wsf2_profile))
		return LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ;

	parent_class->init_from_xml(node, xmlnode);

	if (xmlnode == NULL)
		return LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;

	if (! wsf2_profile->private_data) {
		wsf2_profile->private_data = g_new0(LassoIdWsf2ProfilePrivate, 1);
	}
	epr_node = xmlSecFindChild(xmlnode, BAD_CAST LASSO_IDWSF2_PROFILE_ELEMENT_EPR, BAD_CAST
			LASSO_LASSO_HREF);
	request_node = xmlSecFindChild(xmlnode, BAD_CAST LASSO_IDWSF2_PROFILE_ELEMENT_REQUEST,
			BAD_CAST LASSO_LASSO_HREF);
	response_node = xmlSecFindChild(xmlnode, BAD_CAST LASSO_IDWSF2_PROFILE_ELEMENT_RESPONSE,
			BAD_CAST LASSO_LASSO_HREF);

	if (epr_node) {
		epr_node = xmlSecFindChild(epr_node, BAD_CAST "EndpointReference", BAD_CAST
				LASSO_WSA_HREF);
	}
	if (request_node) {
		request_node = xmlSecFindChild(request_node, BAD_CAST "Envelope", BAD_CAST
				LASSO_SOAP_ENV_HREF);
	}
	if (response_node) {
		response_node = xmlSecFindChild(response_node, BAD_CAST "Envelope", BAD_CAST
				LASSO_SOAP_ENV_HREF);
	}

	if (epr_node) {
		epr = (LassoWsAddrEndpointReference*)lasso_node_new_from_xmlNode(epr_node);
		if (! LASSO_IS_WSA_ENDPOINT_REFERENCE(epr)) {
			lasso_release_gobject(epr);
		}
	}
	if (request_node) {
		request = (LassoSoapEnvelope*)lasso_node_new_from_xmlNode(request_node);
		if (! LASSO_IS_SOAP_ENVELOPE(request)) {
			lasso_release_gobject(request);
		}
	}
	if (response_node) {
		response = (LassoSoapEnvelope*)lasso_node_new_from_xmlNode(response_node);
		if (! LASSO_IS_SOAP_ENVELOPE(response)) {
			lasso_release_gobject(response);
		}
	}

	lasso_assign_new_gobject(wsf2_profile->private_data->epr, epr);
	lasso_assign_new_gobject(wsf2_profile->private_data->soap_envelope_request, request);
	lasso_assign_new_gobject(wsf2_profile->private_data->soap_envelope_response, response);

	return 0;
}

static void
class_init(LassoIdWsf2ProfileClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	klass->parent.parent.get_xmlNode = get_xmlNode;
	klass->parent.parent.init_from_xml = init_from_xml;
}

GType
lasso_idwsf2_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoIdWsf2ProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2Profile),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoIdWsf2Profile", &this_info, 0);
	}
	return this_type;
}

