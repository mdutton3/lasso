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

#ifndef __LASSO_LIB_AUTHN_REQUEST_ENVELOPE_H__
#define __LASSO_LIB_AUTHN_REQUEST_ENVELOPE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "lib_idp_list.h"
#include "lib_authn_request.h"

#define LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE (lasso_lib_authn_request_envelope_get_type())
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, \
				    LassoLibAuthnRequestEnvelope))
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, \
				 LassoLibAuthnRequestEnvelopeClass))
#define LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE))
#define LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE))
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, \
				    LassoLibAuthnRequestEnvelopeClass))

typedef struct _LassoLibAuthnRequestEnvelope LassoLibAuthnRequestEnvelope;
typedef struct _LassoLibAuthnRequestEnvelopeClass LassoLibAuthnRequestEnvelopeClass;

struct _LassoLibAuthnRequestEnvelope {
	LassoNode parent;

	/*< public >*/
	/* <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
	GList *Extension; /* of xmlNode* */
	/* <xs:element ref="AuthnRequest"/> */
	LassoLibAuthnRequest *AuthnRequest;
	/* <xs:element ref="ProviderID"/> */
	char *ProviderID;
	/* <xs:element name="ProviderName" type="xs:string" minOccurs="0"/> */
	char *ProviderName;
	/* <xs:element name="AssertionConsumerServiceURL" type="xs:anyURI"/> */
	char *AssertionConsumerServiceURL;
	/* <xs:element ref="IDPList" minOccurs="0"/> */
	LassoLibIDPList *IDPList;
	/* <xs:element name="IsPassive" type="xs:boolean" minOccurs="0"/> */
	gboolean IsPassive;

};

struct _LassoLibAuthnRequestEnvelopeClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_lib_authn_request_envelope_get_type(void);
LASSO_EXPORT LassoLibAuthnRequestEnvelope* lasso_lib_authn_request_envelope_new(void);

LASSO_EXPORT LassoLibAuthnRequestEnvelope* lasso_lib_authn_request_envelope_new_full(
		LassoLibAuthnRequest *authnRequest,
		char *providerID, char *assertionConsumerServiceURL);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_AUTHN_REQUEST_ENVELOPE_H__ */
