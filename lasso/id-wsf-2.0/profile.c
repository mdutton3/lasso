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

#include "profile.h"
#include "session.h"

#include "../xml/soap_fault.h"
#include "../xml/soap_binding_correlation.h"
#include "../xml/soap_binding_provider.h"
#include "../xml/soap_binding_processing_context.h"
#include "../xml/xml_enc.h"

#include "../xml/ws/wsse_security_header.h"

#include "../xml/saml-2.0/saml2_assertion.h"
#include "../utils.h"

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

LassoSoapEnvelope*
lasso_idwsf2_profile_build_soap_envelope(G_GNUC_UNUSED const char *refToMessageId, G_GNUC_UNUSED const char *providerId)
{
	LassoSoapEnvelope *envelope;
	LassoSoapHeader *header;
	LassoSoapBody *body;

	/* Body */
	body = lasso_soap_body_new();
	body->Id = lasso_build_unique_id(32);
	envelope = lasso_soap_envelope_new(body);

	/* Header */
	header = lasso_soap_header_new();
	envelope->Header = header;

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
	lasso_assign_new_gobject(profile->soap_envelope_request, envelope);

	/* Add identity token (if it exists in the session) in soap header */
	assertion = lasso_session_get_assertion_identity_token(session, service_type);

	/* FIXME: use sb2:TargetIdentity if security mech is :null */
	if (assertion != NULL) {
		wsse_security = lasso_wsse_security_header_new();
		lasso_list_add_new_gobject(wsse_security->any, assertion);
		lasso_list_add_new_gobject(envelope->Header->Other, wsse_security);
	}

	/* Add the given request in soap body */
	lasso_list_add_gobject(envelope->Body->any, request);

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
lasso_idwsf2_profile_process_soap_request_msg(LassoIdWsf2Profile *wsf2_profile, const gchar *message)
{
	LassoProfile *profile = NULL;
	LassoSoapEnvelope *envelope = NULL;
	int rc = 0;

	g_return_val_if_fail(LASSO_IS_IDWSF2_PROFILE(wsf2_profile),
			LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(message != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get soap request */
	profile = LASSO_PROFILE(wsf2_profile);
	lasso_assign_new_gobject(wsf2_profile->soap_envelope_request, lasso_soap_envelope_new_from_message(message));
	if (! LASSO_IS_SOAP_ENVELOPE(wsf2_profile->soap_envelope_request)) {
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}
	envelope = wsf2_profile->soap_envelope_request;
	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL &&
			LASSO_IS_NODE(envelope->Body->any->data)) {
		lasso_assign_gobject(LASSO_PROFILE(profile)->request, (LassoNode*)envelope->Body->any->data);
	} else {
		rc = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	/* Initialize soap response */
	lasso_assign_new_gobject(wsf2_profile->soap_envelope_response, lasso_idwsf2_profile_build_soap_envelope(NULL,
		LASSO_PROVIDER(profile->server)->ProviderID));

	return rc;
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

	lasso_assign_new_gobject(profile->soap_envelope_response, envelope);

	if (envelope != NULL && envelope->Body != NULL && envelope->Body->any != NULL) {
		lasso_assign_gobject(LASSO_PROFILE(profile)->response, LASSO_NODE(envelope->Body->any->data));
	} else {
		res = LASSO_SOAP_ERROR_MISSING_BODY;
	}

	if (LASSO_PROFILE(profile)->response == NULL) {
		res = LASSO_PROFILE_ERROR_MISSING_RESPONSE;
	}

	return res;
}

/**
 * lasso_idwsf2_profile_get_soap_envelope_request:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Return the last parsed SOAP request object.
 *
 * Return value: a #LassoSoapEnvelope object or NULL if no request as ever been parsed with this
 * object. You must free this object.
 */
LassoSoapEnvelope* lasso_idwsf2_profile_get_soap_envelope_request(LassoIdWsf2Profile *idwsf2_profile)
{
	return g_object_ref(idwsf2_profile->soap_envelope_request);

}

/**
 * lasso_idwsf2_profile_get_soap_envelope_response:
 * @idwsf2_profile: a #LassoIdWsf2Profile object
 *
 * Return the last parsed SOAP response object.
 *
 * Return value: a #LassoSoapEnvelope object or NULL if no response as ever been parsed with this
 * object. You must free this object.
 */
LassoSoapEnvelope* lasso_idwsf2_profile_get_soap_envelope_response(LassoIdWsf2Profile *idwsf2_profile)
{
	return g_object_ref(idwsf2_profile->soap_envelope_response);

}


/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
dispose(GObject *object)
{
	LassoIdWsf2Profile *profile = LASSO_IDWSF2_PROFILE(object);

	lasso_release_gobject(profile->soap_envelope_request);
	lasso_release_gobject(profile->soap_envelope_response);

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
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoIdWsf2Profile", &this_info, 0);
	}
	return this_type;
}

