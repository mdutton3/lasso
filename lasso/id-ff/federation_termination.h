/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __LASSO_FEDERATION_TERMINATION_H__
#define __LASSO_FEDERATION_TERMINATION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/environs/profile_context.h>
#include <lasso/protocols/federation_termination_notification.h>

#define LASSO_TYPE_FEDERATION_TERMINATION (lasso_federation_termination_get_type())
#define LASSO_FEDERATION_TERMINATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_FEDERATION_TERMINATION, LassoFederationTermination))
#define LASSO_FEDERATION_TERMINATION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_FEDERATION_TERMINATION, LassoFederationTerminationClass))
#define LASSO_IS_FEDERATION_TERMINATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_FEDERATION_TERMINATION))
#define LASSO_IS_FEDERATION_TERMINATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_FEDERATION_TERMINATION))
#define LASSO_FEDERATION_TERMINATION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_FEDERATION_TERMINATION, LassoFederationTerminationClass)) 

typedef struct _LassoFederationTermination LassoFederationTermination;
typedef struct _LassoFederationTerminationClass LassoFederationTerminationClass;

struct _LassoFederationTermination {
  LassoProfileContext parent;

  /*< private >*/
};

struct _LassoFederationTerminationClass {
  LassoNodeClass parent;

};

LASSO_EXPORT GType                       lasso_federation_termination_get_type                 (void);

LASSO_EXPORT LassoFederationTermination *lasso_federation_termination_new                      (LassoServer *server,
												LassoUser   *user,
												gint         provider_type);
  
LASSO_EXPORT gint                        lasso_federation_termination_build_notification_msg   (LassoFederationTermination *defederation);

LASSO_EXPORT void                        lasso_federation_termination_destroy                  (LassoFederationTermination *defederation);

LASSO_EXPORT gchar*                      lasso_federation_termination_dump                    (LassoFederationTermination *defederation); 

LASSO_EXPORT gint                        lasso_federation_termination_init_notification        (LassoFederationTermination *defederation,
												gchar                 *remote_providerID);
  
LASSO_EXPORT gint                        lasso_federation_termination_process_notification_msg (LassoFederationTermination *defederation,
												gchar                      *request_msg,
												 lassoHttpMethods         request_method);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_FEDERATION_TERMINATION_H__ */
