/* $Id: wsf_profile.h,v 1.13 2006/11/14 17:07:30 Exp $ 
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

#ifndef __LASSO_WSF2_PROFILE_H__
#define __LASSO_WSF2_PROFILE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/id-ff/server.h>
#include <lasso/id-ff/identity.h>
#include <lasso/id-ff/session.h>
#include <lasso/xml/soap_envelope.h>
#include <lasso/xml/soap_binding_provider.h>

#define LASSO_TYPE_WSF2_PROFILE (lasso_wsf2_profile_get_type())
#define LASSO_WSF2_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
       LASSO_TYPE_WSF2_PROFILE, LassoWsf2Profile))
#define LASSO_WSF2_PROFILE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_WSF2_PROFILE, LassoWsf2ProfileClass))
#define LASSO_IS_WSF2_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_WSF2_PROFILE))
#define LASSO_IS_WSF2_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
       LASSO_TYPE_WSF2_PROFILE))
#define LASSO_WSF2_PROFILE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_WSF2_PROFILE, LassoWsf2ProfileClass)) 

typedef struct _LassoWsf2Profile LassoWsf2Profile;
typedef struct _LassoWsf2ProfileClass LassoWsf2ProfileClass;
typedef struct _LassoWsf2ProfilePrivate LassoWsf2ProfilePrivate;

struct _LassoWsf2Profile {
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
	
	LassoWsf2ProfilePrivate *private_data;
};

struct _LassoWsf2ProfileClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsf2_profile_get_type(void);

LASSO_EXPORT LassoSoapEnvelope* lasso_wsf2_profile_build_soap_envelope(const char *refToMessageId,
	const char *providerId);

LASSO_EXPORT gint lasso_wsf2_profile_build_soap_request_msg(LassoWsf2Profile *profile);

LASSO_EXPORT gint lasso_wsf2_profile_process_soap_request_msg(LassoWsf2Profile *profile,
	const gchar *message);

LASSO_EXPORT gint lasso_wsf2_profile_build_soap_response_msg(LassoWsf2Profile *profile);

LASSO_EXPORT gint lasso_wsf2_profile_process_soap_response_msg(LassoWsf2Profile *profile,
	const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSF2_PROFILE_H__ */
