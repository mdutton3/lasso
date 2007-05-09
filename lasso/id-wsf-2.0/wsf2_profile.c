/* $Id: wsf_profile.c,v 1.45 2007/01/05 16:11:02 Exp $
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

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <lasso/xml/soap_fault.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/soap_binding_processing_context.h>

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/providerprivate.h>

#include <lasso/id-wsf-2.0/wsf2_profile.h>
#include <lasso/id-wsf-2.0/wsf2_profile_private.h>

struct _LassoWsf2ProfilePrivate
{
	gboolean dispose_has_run;
	LassoSoapFault *fault;
	gchar *public_key;
	GList *credentials;
};


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

LassoSoapEnvelope*
lasso_wsf2_profile_build_soap_envelope(const char *refToMessageId, const char *providerId)
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

/**
 * lasso_wsf2_profile_get_identity:
 * @profile: a #LassoWsf2Profile
 *
 * Gets the identity bound to @profile.
 *
 * Return value: the identity or NULL if it none was found.  The #LassoIdentity
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoIdentity*
lasso_wsf2_profile_get_identity(LassoWsf2Profile *profile)
{
	if (profile->identity)
		return profile->identity;
	return NULL;
}


/**
 * lasso_wsf2_profile_get_session:
 * @profile: a #LassoWsf2Profile
 *
 * Gets the session bound to @profile.
 *
 * Return value: the session or NULL if it none was found.  The #LassoSession
 *      object is internally allocated and must not be freed by the caller.
 **/
LassoSession*
lasso_wsf2_profile_get_session(LassoWsf2Profile *profile)
{
	if (profile->session == NULL)
		return NULL;

	if (lasso_session_is_empty(profile->session))
		return NULL;

	return profile->session;
}


/**
 * lasso_wsf2_profile_is_identity_dirty:
 * @profile: a #LassoWsf2Profile
 *
 * Checks whether identity has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if identity has changed
 **/
gboolean
lasso_wsf2_profile_is_identity_dirty(LassoWsf2Profile *profile)
{
	return (profile->identity && profile->identity->is_dirty);
}


/**
 * lasso_wsf2_profile_is_session_dirty:
 * @profile: a #LassoWsf2Profile
 *
 * Checks whether session has been modified (and should therefore be saved).
 *
 * Return value: %TRUE if session has changed
 **/
gboolean
lasso_wsf2_profile_is_session_dirty(LassoWsf2Profile *profile)
{
	return (profile->session && profile->session->is_dirty);
}


/**
 * lasso_wsf2_profile_set_identity_from_dump:
 * @profile: a #LassoWsf2Profile
 * @dump: XML identity dump
 *
 * Builds a new #LassoIdentity object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_wsf2_profile_set_identity_from_dump(LassoWsf2Profile *profile, const gchar *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->identity = lasso_identity_new_from_dump(dump);
	if (profile->identity == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP);

	return 0;
}


/**
 * lasso_wsf2_profile_set_session_from_dump:
 * @profile: a #LassoWsf2Profile
 * @dump: XML session dump
 *
 * Builds a new #LassoSession object from XML dump and binds it to @profile.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_wsf2_profile_set_session_from_dump(LassoWsf2Profile *profile, const gchar  *dump)
{
	g_return_val_if_fail(dump != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile->session = lasso_session_new_from_dump(dump);
	if (profile->session == NULL)
		return critical_error(LASSO_PROFILE_ERROR_BAD_SESSION_DUMP);
	profile->session->is_dirty = FALSE;

	return 0;
}


gint
lasso_wsf2_profile_init_soap_request(LassoWsf2Profile *profile, LassoNode *request)
{
	LassoSoapEnvelope *envelope;

	envelope = lasso_wsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	profile->soap_envelope_request = envelope;
	envelope->Body->any = g_list_append(envelope->Body->any, request);

	return 0;
}

gint
lasso_wsf2_profile_build_request_msg(LassoWsf2Profile *profile)
{
	g_return_val_if_fail(LASSO_IS_WSF2_PROFILE(profile),
			     LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile->msg_body = lasso_node_export_to_xml(LASSO_NODE(profile->soap_envelope_request));

	return 0;
}

gint
lasso_wsf2_profile_process_soap_request_msg(LassoWsf2Profile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_WSF2_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get soap request */
	envelope = lasso_soap_envelope_new_from_message(message);

	profile->soap_envelope_request = envelope;

	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL) {
		profile->request = LASSO_NODE(envelope->Body->any->data);
	} else {
		res = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	if (profile->request == NULL) {
		res = LASSO_PROFILE_ERROR_MISSING_REQUEST;
	}

	/* Set soap response */
	envelope = lasso_wsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID);
	profile->soap_envelope_response = envelope;

	return res;
}

gint
lasso_wsf2_profile_build_response_msg(LassoWsf2Profile *profile)
{
	g_return_val_if_fail(LASSO_IS_WSF2_PROFILE(profile),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	profile->msg_body = lasso_node_export_to_xml(LASSO_NODE(profile->soap_envelope_response));

	return 0;
}

gint
lasso_wsf2_profile_process_soap_response_msg(LassoWsf2Profile *profile, const gchar *message)
{
	LassoSoapEnvelope *envelope = NULL;
	int res = 0;

	g_return_val_if_fail(LASSO_IS_WSF2_PROFILE(profile),
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

/*****************************************************************************/
/* overrided parent class methods */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(object);

	if (profile->private_data->dispose_has_run == TRUE)
		return;
	profile->private_data->dispose_has_run = TRUE;

	G_OBJECT_CLASS(parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{ 
	LassoWsf2Profile *profile = LASSO_WSF2_PROFILE(object);
	g_free(profile->private_data);
	profile->private_data = NULL;
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoWsf2Profile *profile)
{
	profile->server = NULL;
	profile->request = NULL;
	profile->response = NULL;
	profile->soap_envelope_request = NULL;
	profile->soap_envelope_response = NULL;
	profile->msg_url = NULL;
	profile->msg_body = NULL;
	
	profile->private_data = g_new0(LassoWsf2ProfilePrivate, 1);
	profile->private_data->dispose_has_run = FALSE;
	profile->private_data->fault = NULL;
	profile->private_data->credentials = NULL;
}

static void
class_init(LassoWsf2ProfileClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_wsf2_profile_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof(LassoWsf2ProfileClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoWsf2Profile),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoWsf2Profile", &this_info, 0);
	}
	return this_type;
}

LassoWsf2Profile*
lasso_wsf2_profile_new(LassoServer *server)
{
	LassoWsf2Profile *profile = NULL;

	g_return_val_if_fail(server != NULL, NULL);

	profile = g_object_new(LASSO_TYPE_WSF2_PROFILE, NULL);

	return profile;
}
