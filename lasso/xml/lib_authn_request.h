/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_LIB_AUTHN_REQUEST_H__
#define __LASSO_LIB_AUTHN_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/samlp_request_abstract.h>
#include <lasso/xml/lib_request_authn_context.h>
#include <lasso/xml/lib_scoping.h>

#define LASSO_TYPE_LIB_AUTHN_REQUEST (lasso_lib_authn_request_get_type())
#define LASSO_LIB_AUTHN_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_REQUEST, LassoLibAuthnRequest))
#define LASSO_LIB_AUTHN_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_REQUEST, LassoLibAuthnRequestClass))
#define LASSO_IS_LIB_AUTHN_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_REQUEST))
#define LASSO_IS_LIB_AUTHN_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_REQUEST))
#define LASSO_LIB_AUTHN_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_REQUEST, LassoLibAuthnRequestClass)) 

typedef struct _LassoLibAuthnRequest LassoLibAuthnRequest;
typedef struct _LassoLibAuthnRequestClass LassoLibAuthnRequestClass;

struct _LassoLibAuthnRequest {
  LassoSamlpRequestAbstract parent;
  /*< private >*/
};

struct _LassoLibAuthnRequestClass {
  LassoSamlpRequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_lib_authn_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_lib_authn_request_new(void);

LASSO_EXPORT void lasso_lib_authn_request_set_affiliationID              (LassoLibAuthnRequest *,
									  const xmlChar *);
  
LASSO_EXPORT void lasso_lib_authn_request_set_assertionConsumerServiceID (LassoLibAuthnRequest *,
									  const xmlChar *);

LASSO_EXPORT void lasso_lib_authn_request_set_consent                    (LassoLibAuthnRequest *,
									  const xmlChar *);

LASSO_EXPORT void lasso_lib_authn_request_set_forceAuthn                 (LassoLibAuthnRequest *,
									  gboolean);

LASSO_EXPORT void lasso_lib_authn_request_set_isPassive                  (LassoLibAuthnRequest *,
									  gboolean);

LASSO_EXPORT void lasso_lib_authn_request_set_nameIDPolicy               (LassoLibAuthnRequest *node,
									  const xmlChar   *nameIDPolicy);

LASSO_EXPORT void lasso_lib_authn_request_set_protocolProfile            (LassoLibAuthnRequest *,
									  const xmlChar *);

LASSO_EXPORT void lasso_lib_authn_request_set_providerID                 (LassoLibAuthnRequest *,
									  const xmlChar *);

LASSO_EXPORT void lasso_lib_authn_request_set_relayState                 (LassoLibAuthnRequest *,
									  const xmlChar *);

LASSO_EXPORT void lasso_lib_authn_request_set_requestAuthnContext        (LassoLibAuthnRequest *,
									  LassoLibRequestAuthnContext *);

LASSO_EXPORT void lasso_lib_authn_request_set_scoping                    (LassoLibAuthnRequest *node,
									  LassoLibScoping *scoping);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_AUTHN_REQUEST_H__ */
