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

#ifndef __LASSO_SAMLP2_AUTHN_REQUEST_H__
#define __LASSO_SAMLP2_AUTHN_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp2_request_abstract.h"
#include "saml2_conditions.h"
#include "samlp2_requested_authn_context.h"
#include "saml2_subject.h"
#include "samlp2_scoping.h"
#include "samlp2_name_id_policy.h"

#define LASSO_TYPE_SAMLP2_AUTHN_REQUEST (lasso_samlp2_authn_request_get_type())
#define LASSO_SAMLP2_AUTHN_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_AUTHN_REQUEST, \
				LassoSamlp2AuthnRequest))
#define LASSO_SAMLP2_AUTHN_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_AUTHN_REQUEST, \
				LassoSamlp2AuthnRequestClass))
#define LASSO_IS_SAMLP2_AUTHN_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_AUTHN_REQUEST))
#define LASSO_IS_SAMLP2_AUTHN_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_AUTHN_REQUEST))
#define LASSO_SAMLP2_AUTHN_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_AUTHN_REQUEST, \
				LassoSamlp2AuthnRequestClass))

typedef struct _LassoSamlp2AuthnRequest LassoSamlp2AuthnRequest;
typedef struct _LassoSamlp2AuthnRequestClass LassoSamlp2AuthnRequestClass;


struct _LassoSamlp2AuthnRequest {
	LassoSamlp2RequestAbstract parent;

	/*< public >*/
	/* elements */
	LassoSaml2Subject *Subject;
	LassoSamlp2NameIDPolicy *NameIDPolicy;
	LassoSaml2Conditions *Conditions;
	LassoSamlp2RequestedAuthnContext *RequestedAuthnContext;
	LassoSamlp2Scoping *Scoping;
	/* attributes */
	gboolean ForceAuthn;
	gboolean IsPassive;
	char *ProtocolBinding;
	int AssertionConsumerServiceIndex;
	char *AssertionConsumerServiceURL;
	int AttributeConsumingServiceIndex;
	char *ProviderName;

	/* This field is deprecated do not use it,
	 * kept for ABI compatibility */
	/*< private >*/
	G_GNUC_DEPRECATED char *relayState;
};


struct _LassoSamlp2AuthnRequestClass {
	LassoSamlp2RequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_samlp2_authn_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_authn_request_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_AUTHN_REQUEST_H__ */
