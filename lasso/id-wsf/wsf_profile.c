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

#include <lasso/id-wsf/wsf_profile.h>
#include <lasso/xml/disco_modify.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/wsse_security.h>
#include <lasso/xml/saml_assertion.h>


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

LassoSoapEnvelope*
lasso_wsf_profile_build_soap_envelope(const char *refToMessageId, const char *providerId)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;
	LassoSoapBindingCorrelation *correlation;
	gchar *messageId, *timestamp;

	/* set Body */
	body = lasso_soap_body_new();
	envelope = lasso_soap_envelope_new(body);

	/* set Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

	/* set Correlation */
	messageId = lasso_build_unique_id(32);
	timestamp = lasso_get_current_time();
	correlation = lasso_soap_binding_correlation_new(messageId, timestamp);
	if (refToMessageId != NULL)
		correlation->refToMessageID = g_strdup(refToMessageId);
	header->Other = g_list_append(header->Other, correlation);

	/* Provider */
	if (providerId) {
		LassoSoapBindingProvider *provider = lasso_soap_binding_provider_new(providerId);
		header->Other = g_list_append(header->Other, provider);
	}

	return envelope;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_wsf_profile_verify_saml_authentication(LassoWsfProfile *profile)
{
	LassoSoapHeader *header;
	LassoWsseSecurity *security = NULL;
	LassoSamlAssertion *credential;
	GList *iter;
	
	header = profile->soap_envelope_request->Header;

	/* Security */
	iter = header->Other;
	while (iter) {
		if (LASSO_IS_WSSE_SECURITY(iter->data) == TRUE) {
			security = LASSO_WSSE_SECURITY(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (!security)
		return -1;
	
	/* Assertion */
	iter = security->any;
	while (iter) {
		if (LASSO_IS_SAML_ASSERTION(iter->data) == TRUE) {
			credential = LASSO_SAML_ASSERTION(iter->data);
			break;
		}
		iter = iter->next;
	}
	if (!credential)
		return -1;
	
	return 0;
}

gboolean
lasso_security_mech_id_is_saml_authentication(const gchar *security_mech_id)
{
	if (!security_mech_id)
		return FALSE;

	if (strcmp(security_mech_id, LASSO_SECURITY_MECH_SAML) == 0 || \
		strcmp(security_mech_id, LASSO_SECURITY_MECH_TLS_SAML) == 0 || \
		strcmp(security_mech_id, LASSO_SECURITY_MECH_CLIENT_TLS_SAML) == 0)
		return TRUE;

	return FALSE;
}

gint
lasso_wsf_profile_add_saml_authentication(LassoWsfProfile *profile, LassoSamlAssertion *credential)
{
	LassoSoapHeader *header;
	LassoWsseSecurity *security;
	GList *iter;

	security = lasso_wsse_security_new();
	security->any = g_list_append(security->any, credential);
	header = profile->soap_envelope_request->Header;
	header->Other = g_list_append(header->Other, security);

	return 0;
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



gint
lasso_wsf_profile_init_soap_request(LassoWsfProfile *profile, LassoNode *request)
{
	LassoSoapEnvelope *envelope;

	envelope = lasso_wsf_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	LASSO_WSF_PROFILE(profile)->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, request);

	return 0;
}

gint
lasso_wsf_profile_build_soap_request_msg(LassoWsfProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* FIXME : set keys */
       	if (LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_request) == TRUE) {
		profile->msg_body = lasso_node_dump(LASSO_NODE(profile->soap_envelope_request));
	}
	else if (LASSO_IS_NODE(profile->request) == TRUE) {
		profile->msg_body = lasso_node_export_to_soap(profile->request);
	}

	return 0;
}

gint
lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *profile)
{
	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	/* FIXME : set keys */
       	if (LASSO_IS_SOAP_ENVELOPE(profile->soap_envelope_response) == TRUE) {
		profile->msg_body = lasso_node_dump(LASSO_NODE(profile->soap_envelope_response));
	}
	else if (LASSO_IS_NODE(profile->response) == TRUE) {
		profile->msg_body = lasso_node_export_to_soap(profile->response);
	}

	return 0;
}

gint
lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile, const gchar *message)
{
	LassoSoapBindingCorrelation *correlation;
	LassoSoapEnvelope *envelope;
	gchar *messageId;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(message));
	profile->soap_envelope_request = envelope;
	profile->request = LASSO_NODE(envelope->Body->any->data); 

	/* FIXME: Process mustUnderstand attribute */

	correlation = envelope->Header->Other->data;

	messageId = correlation->messageID;
	envelope = lasso_wsf_profile_build_soap_envelope(messageId, NULL);
	LASSO_WSF_PROFILE(profile)->soap_envelope_response = envelope;

	return 0;
}

gint
lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	envelope = LASSO_SOAP_ENVELOPE(lasso_node_new_from_dump(message));
	profile->soap_envelope_response = envelope;
	profile->response = LASSO_NODE(envelope->Body->any->data);

	/* FIXME: Process mustUnderstand attribute */

	return 0;
}

LassoSoapBindingProvider *lasso_wsf_profile_set_provider_soap_request(LassoWsfProfile *profile,
								      const char *providerId)
{
	LassoSoapBindingProvider *provider;
	LassoSoapEnvelope *soap_request;
	LassoSoapHeader *header;

	g_return_val_if_fail(LASSO_IS_WSF_PROFILE(profile), NULL);
	g_return_val_if_fail(providerId != NULL, NULL);

	soap_request = profile->soap_envelope_request;
	g_return_val_if_fail(LASSO_IS_SOAP_ENVELOPE(soap_request) == TRUE, NULL);

	header = profile->soap_envelope_request->Header;
	provider = lasso_soap_binding_provider_new(providerId);
	header->Other = g_list_append(header->Other, provider);

	return provider;
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
}

static void
class_init(LassoWsfProfileClass *klass)
{

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

LassoWsfProfile*
lasso_wsf_profile_new(LassoServer *server)
{
	LassoWsfProfile *profile = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	profile = g_object_new(LASSO_TYPE_WSF_PROFILE, NULL);

	return profile;
}
