/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_PROFILE_H__
#define __LASSO_PROFILE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/id-ff/identity.h>
#include <lasso/id-ff/server.h>
#include <lasso/id-ff/session.h>

#include <lasso/xml/samlp_request_abstract.h>
#include <lasso/xml/samlp_response_abstract.h>

#define LASSO_TYPE_PROFILE (lasso_profile_get_type())
#define LASSO_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROFILE, LassoProfile))
#define LASSO_PROFILE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PROFILE, LassoProfileClass))
#define LASSO_IS_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROFILE))
#define LASSO_IS_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROFILE))
#define LASSO_PROFILE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PROFILE, LassoProfileClass)) 

typedef struct _LassoProfile LassoProfile;
typedef struct _LassoProfileClass LassoProfileClass;
typedef struct _LassoProfilePrivate LassoProfilePrivate;

/* Request types (used by SOAP endpoint) */
typedef enum {
	LASSO_REQUEST_TYPE_INVALID = 0,
	LASSO_REQUEST_TYPE_LOGIN = 1,
	LASSO_REQUEST_TYPE_LOGOUT = 2,
	LASSO_REQUEST_TYPE_DEFEDERATION = 3,
	LASSO_REQUEST_TYPE_NAME_REGISTRATION = 4,
	LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING = 5,
	LASSO_REQUEST_TYPE_LECP = 6
} LassoRequestType;

typedef enum {
	LASSO_MESSAGE_TYPE_NONE = 0,
	LASSO_MESSAGE_TYPE_AUTHN_REQUEST,
	LASSO_MESSAGE_TYPE_AUTHN_RESPONSE,
	LASSO_MESSAGE_TYPE_REQUEST,
	LASSO_MESSAGE_TYPE_RESPONSE,
	LASSO_MESSAGE_TYPE_ARTIFACT
} LassoMessageType;

struct _LassoProfile {
	LassoNode parent;

	/*< public >*/
	LassoServer *server;

	LassoSamlpRequestAbstract *request;
	LassoSamlpResponseAbstract *response;

	LassoSamlNameIdentifier *nameIdentifier;

	gchar *remote_providerID;

	gchar *msg_url;
	gchar *msg_body;
	gchar *msg_relayState;

	/*< private >*/
	LassoIdentity *identity;
	LassoSession  *session;

	LassoHttpMethod http_request_method;
	gint signature_status;

	LassoProfilePrivate *private_data;
};

struct _LassoProfileClass {
	LassoNodeClass parent;
};

/* public functions */

LASSO_EXPORT LassoRequestType lasso_profile_get_request_type_from_soap_msg(const gchar *soap);
LASSO_EXPORT gboolean lasso_profile_is_liberty_query(const gchar *query);


/* public methods */

LASSO_EXPORT GType lasso_profile_get_type(void);

LASSO_EXPORT LassoIdentity* lasso_profile_get_identity(LassoProfile *profile);
LASSO_EXPORT LassoSession* lasso_profile_get_session(LassoProfile *profile);
LASSO_EXPORT gboolean lasso_profile_is_identity_dirty(LassoProfile *profile);
LASSO_EXPORT gboolean lasso_profile_is_session_dirty(LassoProfile *profile);

LASSO_EXPORT void lasso_profile_set_response_status(
		LassoProfile *profile, const gchar *statusCodeValue);

LASSO_EXPORT gint lasso_profile_set_identity_from_dump(LassoProfile *profile, const gchar *dump);
LASSO_EXPORT gint lasso_profile_set_session_from_dump(LassoProfile *profile, const gchar *dump);
LASSO_EXPORT LassoSamlNameIdentifier* lasso_profile_get_nameIdentifier(LassoProfile *profile);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROFILE_H__ */
