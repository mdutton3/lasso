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

#ifndef __LASSO_LECP_H__
#define __LASSO_LECP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#include <lasso/xml/lib_authn_request_envelope.h>
#include <lasso/xml/lib_authn_response_envelope.h>

#include <lasso/environs/login.h>

#define LASSO_TYPE_LECP (lasso_lecp_get_type())
#define LASSO_LECP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LECP, LassoLecp))
#define LASSO_LECP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LECP, LassoLecpClass))
#define LASSO_IS_LECP(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LECP))
#define LASSO_IS_LECP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LECP))
#define LASSO_LECP_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LECP, LassoLecpClass)) 

typedef struct _LassoLecp LassoLecp;
typedef struct _LassoLecpClass LassoLecpClass;

struct _LassoLecp {
  LassoLogin parent;

  /*< public >*/
  LassoNode *authnRequestEnvelope;
  LassoNode *authnResponseEnvelope;

  gchar *assertionConsumerServiceURL;

  /*< private >*/
};

struct _LassoLecpClass {
  LassoLoginClass parent_class;
};

LASSO_EXPORT GType      lasso_lecp_get_type                            (void);

LASSO_EXPORT LassoLecp* lasso_lecp_new                                 (LassoServer *server);

LASSO_EXPORT gint       lasso_lecp_build_authn_request_envelope_msg    (LassoLecp *lecp);

LASSO_EXPORT gint       lasso_lecp_build_authn_request_msg             (LassoLecp   *lecp,
									const gchar *remote_providerID);

LASSO_EXPORT gint       lasso_lecp_build_authn_response_msg            (LassoLecp *lecp);

LASSO_EXPORT gint lasso_lecp_build_authn_response_envelope_msg(LassoLecp   *lecp,
		gint authentication_result,
		gboolean     is_consent_obtained,
		const char *authenticationMethod,
		const char *authenticationInstant,
		const char *reauthenticateOnOrAfter,
		const char *notBefore,
		const char *notOnOrAfter);

LASSO_EXPORT void       lasso_lecp_destroy                             (LassoLecp *lecp);

LASSO_EXPORT gint       lasso_lecp_init_authn_request                  (LassoLecp *lecp);

LASSO_EXPORT gint       lasso_lecp_process_authn_request_msg           (LassoLecp       *lecp,
									gchar           *authn_request_msg);

LASSO_EXPORT gint       lasso_lecp_process_authn_request_envelope_msg  (LassoLecp *lecp,
									gchar     *request_msg);
  
LASSO_EXPORT gint       lasso_lecp_process_authn_response_envelope_msg (LassoLecp *lecp,
									gchar     *response_msg);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LECP_H__ */
