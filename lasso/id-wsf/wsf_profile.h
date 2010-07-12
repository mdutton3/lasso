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

#ifndef __LASSO_WSF_PROFILE_H__
#define __LASSO_WSF_PROFILE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include "../id-ff/server.h"
#include "../id-ff/identity.h"
#include "../id-ff/session.h"
#include "../xml/soap-1.1/soap_envelope.h"
#include "../xml/soap_binding_provider.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/saml_assertion.h"
#include "../xml/disco_description.h"
#include "../xml/disco_resource_offering.h"
#include "../xml/disco_description.h"

#define LASSO_TYPE_WSF_PROFILE (lasso_wsf_profile_get_type())
#define LASSO_WSF_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
	   LASSO_TYPE_WSF_PROFILE, LassoWsfProfile))
#define LASSO_WSF_PROFILE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_WSF_PROFILE, LassoWsfProfileClass))
#define LASSO_IS_WSF_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_WSF_PROFILE))
#define LASSO_IS_WSF_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
	   LASSO_TYPE_WSF_PROFILE))
#define LASSO_WSF_PROFILE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_WSF_PROFILE, LassoWsfProfileClass))

typedef struct _LassoWsfProfile LassoWsfProfile;
typedef struct _LassoWsfProfileClass LassoWsfProfileClass;
typedef struct _LassoWsfProfilePrivate LassoWsfProfilePrivate;

struct _LassoWsfProfile {
	LassoNode parent;

	LassoServer *server;

	LassoNode *request;
	LassoNode *response;

	LassoSoapEnvelope *soap_envelope_request;
	LassoSoapEnvelope *soap_envelope_response;

	gchar *msg_url;
	gchar *msg_body;

	/*< private >*/
	LassoIdentity *identity;
	LassoSession  *session;

	LassoWsfProfilePrivate *private_data;
};

struct _LassoWsfProfileClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsf_profile_get_type(void);

G_GNUC_DEPRECATED LASSO_EXPORT lasso_error_t lasso_wsf_profile_move_credentials(LassoWsfProfile *src,
	LassoWsfProfile *dest);

LASSO_EXPORT LassoIdentity* lasso_wsf_profile_get_identity(const LassoWsfProfile *profile);
LASSO_EXPORT LassoSession* lasso_wsf_profile_get_session(const LassoWsfProfile *profile);
LASSO_EXPORT gboolean lasso_wsf_profile_is_identity_dirty(const LassoWsfProfile *profile);
LASSO_EXPORT gboolean lasso_wsf_profile_is_session_dirty(const LassoWsfProfile *profile);
LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_identity_from_dump(LassoWsfProfile *profile,
	const gchar *dump);
LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_session_from_dump(LassoWsfProfile *profile,
	const gchar *dump);

G_GNUC_DEPRECATED LASSO_EXPORT LassoSoapEnvelope* lasso_wsf_profile_build_soap_envelope(
	const char *refToMessageId,
	const char *providerId);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_build_soap_request_msg(LassoWsfProfile *profile);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *profile);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_init_soap_request(LassoWsfProfile *profile, LassoNode *request);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_init_soap_response(LassoWsfProfile *profile,
		LassoNode *response);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile,
	const gchar *message, const gchar *security_mech_id);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile,
	const gchar *message);

G_GNUC_DEPRECATED LASSO_EXPORT LassoSoapBindingProvider* lasso_wsf_profile_set_provider_soap_request(
	LassoWsfProfile *profile, const char *providerId);

LASSO_EXPORT LassoWsfProfile* lasso_wsf_profile_new(LassoServer *server);

LASSO_EXPORT LassoWsfProfile* lasso_wsf_profile_new_full(LassoServer *server,
	LassoDiscoResourceOffering *offering);

G_GNUC_DEPRECATED LASSO_EXPORT gboolean lasso_wsf_profile_principal_is_online(
	LassoWsfProfile *profile);

G_GNUC_DEPRECATED LASSO_EXPORT lasso_error_t lasso_wsf_profile_add_credential(LassoWsfProfile *profile,
	xmlNode *credential);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_description_from_offering(
		LassoWsfProfile *profile,
		const LassoDiscoResourceOffering *offering,
		const char *security_mech_id);

LASSO_EXPORT void lasso_wsf_profile_set_description(LassoWsfProfile *profile,
		LassoDiscoDescription *description);

LASSO_EXPORT LassoDiscoDescription *lasso_wsf_profile_get_description(
	const LassoWsfProfile *profile);

LASSO_EXPORT LassoDiscoResourceOffering *lasso_wsf_profile_get_resource_offering(
	LassoWsfProfile *profile);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_security_mech_id(LassoWsfProfile *profile,
	const char *security_mech_id);

LASSO_EXPORT const char *lasso_wsf_profile_get_security_mech_id(LassoWsfProfile *profile);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_init(LassoWsfProfile *profile, LassoServer *server,
	LassoDiscoResourceOffering *offering);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_get_remote_provider(LassoWsfProfile *wsf_profile,
		LassoProvider **provider);

LASSO_EXPORT const char* lasso_wsf_profile_get_remote_provider_id(LassoWsfProfile *wsf_profile);

LASSO_EXPORT LassoSoapFault* lasso_wsf_profile_get_soap_fault(LassoWsfProfile *wsf_profile);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_soap_fault(LassoWsfProfile *wsf_profile, LassoSoapFault *soap_fault);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_status_code(LassoWsfProfile *wsf_profile, const char *code);

LASSO_EXPORT const char* lasso_wsf_profile_get_status_code(LassoWsfProfile *wsf_profile);

LASSO_EXPORT lasso_error_t lasso_wsf_profile_set_msg_url_from_description(LassoWsfProfile *wsf_profile);

LASSO_EXPORT void lasso_wsf_profile_set_resource_offering(LassoWsfProfile *profile,
		LassoDiscoResourceOffering *offering);

#define lasso_wsf_profile_helper_assign_resource_id(from,to) \
	if ((from)->ResourceID) {\
		lasso_assign_gobject((to)->ResourceID, (from)->ResourceID); \
	} else if ((from)->EncryptedResourceID) {\
		lasso_assign_gobject((to)->EncryptedResourceID, (from)->EncryptedResourceID); \
	}

#define lasso_wsf_profile_helper_set_status(message, code) \
	{ \
		lasso_assign_new_gobject(message->Status, lasso_utility_status_new(code)); \
	}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSF_PROFILE_H__ */
