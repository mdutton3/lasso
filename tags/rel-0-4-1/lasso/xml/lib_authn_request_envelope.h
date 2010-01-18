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

#ifndef __LASSO_LIB_AUTHN_REQUEST_ENVELOPE_H__
#define __LASSO_LIB_AUTHN_REQUEST_ENVELOPE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/lib_idp_list.h>
#include <lasso/xml/lib_authn_request.h>

#define LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE (lasso_lib_authn_request_envelope_get_type())
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, LassoLibAuthnRequestEnvelope))
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, LassoLibAuthnRequestEnvelopeClass))
#define LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE))
#define LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE))
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, LassoLibAuthnRequestEnvelopeClass)) 

typedef struct _LassoLibAuthnRequestEnvelope LassoLibAuthnRequestEnvelope;
typedef struct _LassoLibAuthnRequestEnvelopeClass LassoLibAuthnRequestEnvelopeClass;

struct _LassoLibAuthnRequestEnvelope {
  LassoNode parent;

  /*< private >*/
};

struct _LassoLibAuthnRequestEnvelopeClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType      lasso_lib_authn_request_envelope_get_type         (void);

LASSO_EXPORT LassoNode* lasso_lib_authn_request_envelope_new              (void);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_extension    (LassoLibAuthnRequestEnvelope *node,
									   LassoNode                    *extension);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_authnRequest (LassoLibAuthnRequestEnvelope *node,
									   LassoLibAuthnRequest         *request);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_assertionConsumerServiceURL (LassoLibAuthnRequestEnvelope *node,
											  const xmlChar *assertionConsumerServiceURL);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_providerID   (LassoLibAuthnRequestEnvelope *node,
									   const xmlChar                *providerID);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_providerName (LassoLibAuthnRequestEnvelope *node,
									   const xmlChar                *providerName);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_idpList      (LassoLibAuthnRequestEnvelope *node,
									   LassoLibIDPList              *idpList);

LASSO_EXPORT void       lasso_lib_authn_request_envelope_set_isPassive    (LassoLibAuthnRequestEnvelope *node,
									   gboolean                      isPassive);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_AUTHN_REQUEST_ENVELOPE_H__ */
