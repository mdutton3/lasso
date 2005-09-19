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

#ifndef __LASSO_WSF_PROFILE_H__
#define __LASSO_WSF_PROFILE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/identity.h>
#include <lasso/id-ff/session.h>
#include <lasso/xml/soap_envelope.h>
#include <lasso/xml/soap_binding_provider.h>
#include <lasso/xml/saml_assertion.h>

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
};

struct _LassoWsfProfileClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsf_profile_get_type(void);

/* FIXME: Should not be here */
LASSO_EXPORT gboolean lasso_security_mech_id_is_saml_authentication(
	const gchar *security_mech_id);

LASSO_EXPORT gint lasso_wsf_profile_add_saml_authentication(LassoWsfProfile *profile,
	LassoSamlAssertion *credential);

LASSO_EXPORT LassoIdentity* lasso_wsf_profile_get_identity(LassoWsfProfile *profile);
LASSO_EXPORT LassoSession* lasso_wsf_profile_get_session(LassoWsfProfile *profile);
LASSO_EXPORT gboolean lasso_wsf_profile_is_identity_dirty(LassoWsfProfile *profile);
LASSO_EXPORT gboolean lasso_wsf_profile_is_session_dirty(LassoWsfProfile *profile);

LASSO_EXPORT gint lasso_wsf_profile_set_identity_from_dump(LassoWsfProfile *profile,
		const gchar *dump);
LASSO_EXPORT gint lasso_wsf_profile_set_session_from_dump(LassoWsfProfile *profile,
		const gchar *dump);

/* FIXME: must be private method */
LASSO_EXPORT LassoSoapEnvelope* lasso_wsf_profile_build_soap_envelope(const char *refToMessageId,
		const char *providerId);

LASSO_EXPORT gint lasso_wsf_profile_build_soap_request_msg(LassoWsfProfile *profile);

LASSO_EXPORT gint lasso_wsf_profile_build_soap_response_msg(LassoWsfProfile *profile);

LASSO_EXPORT gint lasso_wsf_profile_init_soap_request(LassoWsfProfile *profile,
						      LassoNode *request);

LASSO_EXPORT gint lasso_wsf_profile_process_soap_request_msg(LassoWsfProfile *profile,
							     const gchar *message);

LASSO_EXPORT gint lasso_wsf_profile_process_soap_response_msg(LassoWsfProfile *profile,
							      const gchar *message);

LASSO_EXPORT LassoSoapBindingProvider* lasso_wsf_profile_set_provider_soap_request(
	LassoWsfProfile *profile,
	const char *providerId);

LASSO_EXPORT LassoWsfProfile* lasso_wsf_profile_new(LassoServer *server);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSF_PROFILE_H__ */
