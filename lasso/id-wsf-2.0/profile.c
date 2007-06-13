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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/serverprivate.h>
#include <lasso/id-ff/providerprivate.h>

#include <lasso/id-wsf-2.0/profile.h>
#include <lasso/id-wsf-2.0/session.h>

#include <lasso/xml/soap_fault.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/soap_binding_processing_context.h>
#include <lasso/xml/xml_enc.h>

#include <lasso/xml/ws/wsse_200401_security.h>

#include <lasso/xml/saml-2.0/saml2_assertion.h>

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

LassoSoapEnvelope*
lasso_idwsf2_profile_build_soap_envelope(const char *refToMessageId, const char *providerId)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;

	/* Body */
	body = lasso_soap_body_new();
	body->id = lasso_build_unique_id(32);
	envelope = lasso_soap_envelope_new(body);

	/* Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	/* FIXME : May be integrated later when we implement id-wsf 2.0 soap headers */
	/* Provider */
/* 	if (providerId) { */
/* 		LassoSoapBindingProvider *provider = lasso_soap_binding_provider_new(providerId); */
/* 		provider->id = lasso_build_unique_id(32); */
/* 		header->Other = g_list_append(header->Other, provider); */
/* 	} */

	return envelope;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_idwsf2_profile_init_soap_request(LassoProfile *profile, LassoNode *request,
	gchar *service_type)
{
	LassoSoapEnvelope *envelope;
	LassoSession *session = profile->session;
	LassoSaml2Assertion *assertion;
	LassoWsse200401Security *wsse_security;

	/* Initialise soap envelope */
	envelope = lasso_idwsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	profile->soap_envelope_request = envelope;

	/* Add identity token (if it exists in the session) in soap header */
	assertion = lasso_session_get_assertion_identity_token(session, service_type);

	if (assertion != NULL) {
		wsse_security = lasso_wsse_200401_security_new();
		wsse_security->any = g_list_append(wsse_security->any, assertion);

		envelope = profile->soap_envelope_request;
		envelope->Header->Other = g_list_append(envelope->Header->Other, wsse_security);
	}
	
	/* Add the given request in soap body */
	envelope->Body->any = g_list_append(envelope->Body->any, request);

	return 0;
}

gint
lasso_idwsf2_profile_build_request_msg(LassoProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile->msg_body = lasso_node_export_to_xml(LASSO_NODE(profile->soap_envelope_request));

	return 0;
}

gint
lasso_idwsf2_profile_process_soap_request_msg(LassoProfile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	LassoSaml2Assertion *assertion;
	LassoWsse200401Security *wsse_security;
	LassoSaml2EncryptedElement *encrypted_id = NULL;
	LassoNode *decrypted_name_id = NULL;
	xmlSecKey *encryption_private_key = NULL;
	GList *i;
	GList *j;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get soap request */
	envelope = lasso_soap_envelope_new_from_message(message);

	profile->soap_envelope_request = envelope;

	if (profile->nameIdentifier != NULL) {
		lasso_node_destroy(profile->nameIdentifier);
		profile->nameIdentifier = NULL;
	}

	/* Get NameIdentifier (if exists) from the soap header */
	for (i = g_list_first(envelope->Header->Other); i != NULL; i = g_list_next(i)) {
		if (! LASSO_IS_WSSE_200401_SECURITY(i->data)) {
			continue;
		}
		wsse_security = LASSO_WSSE_200401_SECURITY(i->data);
		for (j = g_list_first(wsse_security->any); j != NULL; j = g_list_next(j)) {
			if (! LASSO_IS_SAML2_ASSERTION(j->data)) {
				continue;
			}
			assertion = LASSO_SAML2_ASSERTION(j->data);
			if (assertion->Subject == NULL) {
				continue;
			}
			if (LASSO_IS_SAML2_NAME_ID(assertion->Subject->NameID)) {
				profile->nameIdentifier = g_object_ref(assertion->Subject->NameID);
			} else if (LASSO_IS_SAML2_ENCRYPTED_ELEMENT(
					assertion->Subject->EncryptedID)) {
				encrypted_id = assertion->Subject->EncryptedID;
			} else {
				continue;
			}
			break;
		}
		break;
	}

	/* Decrypt NameID */
	encryption_private_key = profile->server->private_data->encryption_private_key;
	if (profile->nameIdentifier == NULL && encrypted_id != NULL
			&& encryption_private_key != NULL) {
		decrypted_name_id = lasso_node_decrypt(encrypted_id, encryption_private_key);
		if (LASSO_IS_SAML2_NAME_ID(decrypted_name_id)) {
			profile->nameIdentifier = decrypted_name_id;
		}
	}

	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL) {
		profile->request = LASSO_NODE(envelope->Body->any->data);
	} else {
		res = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	if (profile->request == NULL) {
		res = LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}

	/* Set soap response */
	envelope = lasso_idwsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	profile->soap_envelope_response = envelope;

	return res;
}

gint
lasso_idwsf2_profile_build_response_msg(LassoProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile->msg_body = lasso_node_export_to_xml(LASSO_NODE(profile->soap_envelope_response));

	return 0;
}

gint
lasso_idwsf2_profile_process_soap_response_msg(LassoProfile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get soap response */
	envelope = lasso_soap_envelope_new_from_message(message);

	profile->soap_envelope_response = envelope;

	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL) {
		profile->response = LASSO_NODE(envelope->Body->any->data);
	} else {
		res = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	if (profile->response == NULL) {
		res = LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}

	return res;
}

