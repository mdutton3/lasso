/* $Id: wsf_profile.h,v 1.13 2006/11/14 17:07:30 Exp $ 
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

#ifndef __LASSO_IDWSF2_PROFILE_H__
#define __LASSO_IDWSF2_PROFILE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/id-ff/profile.h>
#include <lasso/xml/soap_envelope.h>

#define LASSO_TYPE_IDWSF2_PROFILE (lasso_idwsf2_profile_get_type())
#define LASSO_IDWSF2_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), \
       LASSO_TYPE_IDWSF2_PROFILE, LassoIdWsf2Profile))
#define LASSO_IDWSF2_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), \
       LASSO_TYPE_IDWSF2_PROFILE, LassoIdWsf2ProfileClass))
#define LASSO_IS_IDWSF2_PROFILE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
       LASSO_TYPE_IDWSF2_PROFILE))
#define LASSO_IS_IDWSF2_PROFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), \
       LASSO_TYPE_IDWSF2_PROFILE))
#define LASSO_IDWSF2_PROFILE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), \
       LASSO_TYPE_IDWSF2_PROFILE, LassoIdWsf2ProfileClass)) 


typedef struct _LassoIdWsf2Profile LassoIdWsf2Profile;
typedef struct _LassoIdWsf2ProfileClass LassoIdWsf2ProfileClass;
typedef struct _LassoIdWsf2ProfilePrivate LassoIdWsf2ProfilePrivate;

struct _LassoIdWsf2Profile {
	LassoProfile parent;

	/*< private >*/
	LassoSoapEnvelope *soap_envelope_request;
	LassoSoapEnvelope *soap_envelope_response;

	LassoIdWsf2ProfilePrivate *private_data;
};

struct _LassoIdWsf2ProfileClass {
	LassoProfileClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_profile_get_type(void);

LASSO_EXPORT gint lasso_idwsf2_profile_init_soap_request(LassoIdWsf2Profile *profile,
	LassoNode *request, gchar *service_type);

LASSO_EXPORT gint lasso_idwsf2_profile_build_request_msg(LassoIdWsf2Profile *profile);

LASSO_EXPORT gint lasso_idwsf2_profile_process_soap_request_msg(LassoIdWsf2Profile *profile,
	const gchar *message);

LASSO_EXPORT gint lasso_idwsf2_profile_build_response_msg(LassoIdWsf2Profile *profile);

LASSO_EXPORT gint lasso_idwsf2_profile_process_soap_response_msg(LassoIdWsf2Profile *profile,
	const gchar *message);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_PROFILE_H__ */

