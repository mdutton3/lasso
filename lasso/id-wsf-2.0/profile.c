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

#include <lasso/xml/ws/wsse_security_header.h>

#include <lasso/xml/saml-2.0/saml2_assertion.h>

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoSoapEnvelope*
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
lasso_idwsf2_profile_init_soap_request(LassoIdWsf2Profile *profile, LassoNode *request,
	gchar *service_type)
{
	LassoSoapEnvelope *envelope;
	LassoSession *session = LASSO_PROFILE(profile)->session;
	LassoSaml2Assertion *assertion;
	LassoWsSec1SecurityHeader *wsse_security;

	/* Initialise soap envelope */
	envelope = lasso_idwsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(LASSO_PROFILE(profile)->server)->ProviderID);
	profile->soap_envelope_request = envelope;

	/* Add identity token (if it exists in the session) in soap header */
	assertion = lasso_session_get_assertion_identity_token(session, service_type);

	if (assertion != NULL) {
		wsse_security = lasso_wsse_security_header_new();
		wsse_security->any = g_list_append(wsse_security->any, assertion);

		envelope->Header->Other = g_list_append(envelope->Header->Other, wsse_security);
	}
	
	/* Add the given request in soap body */
	envelope->Body->any = g_list_append(envelope->Body->any, request);

	return 0;
}

gint
lasso_idwsf2_profile_build_request_msg(LassoIdWsf2Profile *profile)
{
	g_return_val_if_fail(LASSO_IS_IDWSF2_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	LASSO_PROFILE(profile)->msg_body = lasso_node_export_to_xml(
			LASSO_NODE(profile->soap_envelope_request));

	return 0;
}

gint
lasso_idwsf2_profile_process_soap_request_msg(LassoIdWsf2Profile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	LassoSaml2Assertion *assertion;
	LassoWsSec1SecurityHeader *wsse_security;
	LassoSaml2EncryptedElement *encrypted_id = NULL;
	LassoNode *decrypted_name_id = NULL;
	xmlSecKey *encryption_private_key = NULL;
	GList *i;
	GList *j;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_PROFILE(profile),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get soap request */
	envelope = lasso_soap_envelope_new_from_message(message);

	profile->soap_envelope_request = envelope;

	if (LASSO_PROFILE(profile)->nameIdentifier != NULL) {
		lasso_node_destroy(LASSO_PROFILE(profile)->nameIdentifier);
		LASSO_PROFILE(profile)->nameIdentifier = NULL;
	}

	/* Get NameIdentifier (if exists) from the soap header */
	for (i = g_list_first(envelope->Header->Other); i != NULL; i = g_list_next(i)) {
		if (! LASSO_IS_WSSE_SECURITY_HEADER(i->data)) {
			continue;
		}
		wsse_security = LASSO_WSSE_SECURITY_HEADER(i->data);
		for (j = g_list_first(wsse_security->any); j != NULL; j = g_list_next(j)) {
			if (! LASSO_IS_SAML2_ASSERTION(j->data)) {
				continue;
			}
			assertion = LASSO_SAML2_ASSERTION(j->data);
			if (assertion->Subject == NULL) {
				continue;
			}
			if (LASSO_IS_SAML2_NAME_ID(assertion->Subject->NameID)) {
				LASSO_PROFILE(profile)->nameIdentifier = g_object_ref(
						assertion->Subject->NameID);
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
	encryption_private_key = LASSO_PROFILE(
			profile)->server->private_data->encryption_private_key;
	if (LASSO_PROFILE(profile)->nameIdentifier == NULL && encrypted_id != NULL
			&& encryption_private_key != NULL) {
		decrypted_name_id = lasso_node_decrypt(encrypted_id, encryption_private_key);
		if (LASSO_IS_SAML2_NAME_ID(decrypted_name_id)) {
			LASSO_PROFILE(profile)->nameIdentifier = decrypted_name_id;
		}
		assertion->Subject->EncryptedID = NULL;
	}

	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL) {
		LASSO_PROFILE(profile)->request = LASSO_NODE(envelope->Body->any->data);
	} else {
		res = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	if (LASSO_PROFILE(profile)->request == NULL) {
		res = LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}

	/* Set soap response */
	envelope = lasso_idwsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(LASSO_PROFILE(profile)->server)->ProviderID);
	profile->soap_envelope_response = envelope;

	return res;
}

gint
lasso_idwsf2_profile_build_response_msg(LassoIdWsf2Profile *profile)
{
	g_return_val_if_fail(LASSO_IS_IDWSF2_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	LASSO_PROFILE(profile)->msg_body = lasso_node_export_to_xml(LASSO_NODE(
		profile->soap_envelope_response));

	return 0;
}

gint
lasso_idwsf2_profile_process_soap_response_msg(LassoIdWsf2Profile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get soap response */
	envelope = lasso_soap_envelope_new_from_message(message);

	profile->soap_envelope_response = envelope;

	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL) {
		LASSO_PROFILE(profile)->response = LASSO_NODE(envelope->Body->any->data);
	} else {
		res = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	if (LASSO_PROFILE(profile)->response == NULL) {
		res = LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}

	return res;
}
/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoIdWsf2Profile *profile = LASSO_IDWSF2_PROFILE(object);

	if (profile->soap_envelope_request) {
		lasso_node_destroy(LASSO_NODE(profile->soap_envelope_request));
		profile->soap_envelope_request = NULL;
	}

	if (profile->soap_envelope_response) {
		lasso_node_destroy(LASSO_NODE(profile->soap_envelope_response));
		profile->soap_envelope_response = NULL;
	}
	G_OBJECT_CLASS(parent_class)->dispose(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2Profile *profile)
{
	profile->soap_envelope_request = NULL;
	profile->soap_envelope_response = NULL;
}

static void
class_init(LassoIdWsf2ProfileClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
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
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoIdWsf2Profile", &this_info, 0);
	}
	return this_type;
}

