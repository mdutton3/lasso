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

#include <lasso/xml/strings.h>
#include <lasso/xml/tools.h>

#include <lasso/environs/server.h>
#include <lasso/environs/identity.h>
#include <lasso/environs/session.h>

#define LASSO_TYPE_PROFILE (lasso_profile_get_type())
#define LASSO_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROFILE, LassoProfile))
#define LASSO_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PROFILE, LassoProfileClass))
#define LASSO_IS_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROFILE))
#define LASSO_IS_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROFILE))
#define LASSO_PROFILE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PROFILE, LassoProfileClass)) 

typedef struct _LassoProfile LassoProfile;
typedef struct _LassoProfileClass LassoProfileClass;
typedef struct _LassoProfilePrivate LassoProfilePrivate;

/* Request types (used by SOAP endpoint) */
typedef enum {
  lassoRequestTypeInvalid = 0,
  lassoRequestTypeLogin = 1,
  lassoRequestTypeLogout = 2,
  lassoRequestTypeDefederation = 3,
  lassoRequestTypeRegisterNameIdentifier = 4, /* obsolete, use lassoRequestTypeNameRegistration instead */
  lassoRequestTypeNameRegistration = 4,
  lassoRequestTypeNameIdentifierMapping = 5,
  lassoRequestTypeLecp = 6
} lassoRequestType;

typedef enum {
  lassoHttpMethodAny = -1,
  lassoHttpMethodSelfAddressed,
  lassoHttpMethodGet,
  lassoHttpMethodPost,
  lassoHttpMethodRedirect,
  lassoHttpMethodSoap
} lassoHttpMethod;

typedef enum {
  lassoMessageTypeNone = 0,
  lassoMessageTypeAuthnRequest,
  lassoMessageTypeAuthnResponse,
  lassoMessageTypeRequest,
  lassoMessageTypeResponse,
  lassoMessageTypeArtifact
} lassoMessageType;

struct _LassoProfile {
  GObject parent;

  /*< public >*/
  LassoServer *server;

  LassoNode *request;
  LassoNode *response;

  gchar *nameIdentifier;

  gchar *remote_providerID;

  gchar *msg_url;
  gchar *msg_body;
  gchar *msg_relayState;

  /*< private >*/
  LassoIdentity *identity;
  LassoSession  *session;

  lassoMessageType  request_type;
  lassoMessageType  response_type;
  lassoProviderType provider_type;

  lassoHttpMethod http_request_method;
  gint signature_status;

  LassoProfilePrivate *private;
};

struct _LassoProfileClass {
  GObjectClass parent;
};

/* public functions */

LASSO_EXPORT lassoRequestType lasso_profile_get_request_type_from_soap_msg (const gchar *soap);

LASSO_EXPORT gboolean         lasso_profile_is_liberty_query               (const gchar *query);

/* public methods */

LASSO_EXPORT GType          lasso_profile_get_type                       (void);

LASSO_EXPORT LassoProfile*  lasso_profile_new                            (LassoServer   *server,
									  LassoIdentity *identity,
									  LassoSession  *session);

LASSO_EXPORT gchar*         lasso_profile_dump                           (LassoProfile *ctx,
									  const gchar  *name);

LASSO_EXPORT LassoIdentity* lasso_profile_get_identity                   (LassoProfile *ctx);

LASSO_EXPORT gchar*         lasso_profile_get_remote_providerID          (LassoProfile *ctx);

LASSO_EXPORT LassoSession*  lasso_profile_get_session                    (LassoProfile *ctx);

LASSO_EXPORT gboolean       lasso_profile_is_identity_dirty              (LassoProfile *ctx);

LASSO_EXPORT gboolean       lasso_profile_is_session_dirty               (LassoProfile *ctx);

LASSO_EXPORT gint           lasso_profile_set_remote_providerID          (LassoProfile *ctx,
									  gchar        *providerID);

LASSO_EXPORT void           lasso_profile_set_response_status            (LassoProfile *ctx,
									  const gchar  *statusCodeValue);

LASSO_EXPORT gint           lasso_profile_set_identity                   (LassoProfile  *ctx,
									  LassoIdentity *identity);

LASSO_EXPORT gint           lasso_profile_set_identity_from_dump         (LassoProfile *ctx,
									  const gchar  *dump);

LASSO_EXPORT gint           lasso_profile_set_session                    (LassoProfile *ctx,
									  LassoSession *session);

LASSO_EXPORT gint           lasso_profile_set_session_from_dump          (LassoProfile *ctx,
									  const gchar  *dump);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROFILE_H__ */
