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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_LIB_AUTHN_REQUEST_H__
#define __LASSO_LIB_AUTHN_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp_request_abstract.h"
#include "lib_request_authn_context.h"
#include "lib_scoping.h"

#define LASSO_TYPE_LIB_AUTHN_REQUEST (lasso_lib_authn_request_get_type())
#define LASSO_LIB_AUTHN_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_REQUEST, LassoLibAuthnRequest))
#define LASSO_LIB_AUTHN_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_REQUEST, LassoLibAuthnRequestClass))
#define LASSO_IS_LIB_AUTHN_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_REQUEST))
#define LASSO_IS_LIB_AUTHN_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_REQUEST))
#define LASSO_LIB_AUTHN_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_REQUEST, LassoLibAuthnRequestClass))

typedef struct _LassoLibAuthnRequest LassoLibAuthnRequest;
typedef struct _LassoLibAuthnRequestClass LassoLibAuthnRequestClass;

/**
 * LassoLibAuthnRequest:
 *
 * @ProviderID isthe service provider identifier, this field will often be
 * filled with lasso_login_init_authn_request()
 *
 * @nameIDPolicy tells the identity provider about the policy to use for
 * federation; it must be one of #LASSO_LIB_NAMEID_POLICY_TYPE_NONE,
 * #LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME,
 * #LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED or
 * #LASSO_LIB_NAMEID_POLICY_TYPE_ANY.
 *
 * @IsPassive; if %TRUE (default) it tells the identity provider not to
 * interact with the user.
 *
 * @ForceAuthn; only used if @IsPassive is %FALSE, it tells the identity
 * provider to force authentication of the user even when already
 * authenticated.
 *
 * @ProtocolProfile is the Single Sign-On and Federation profile to adopt;
 * either #LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART (which is the default value)
 * or #LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST.
 *
 */
struct _LassoLibAuthnRequest {
	LassoSamlpRequestAbstract parent;

	/*< public >*/
	/* <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
	GList *Extension; /* of xmlNode* */
	/* <xs:element ref="ProviderID"/> */
	char *ProviderID;
	/* <xs:element ref="AffiliationID" minOccurs="0"/> */
	char *AffiliationID;
	/* <xs:element ref="NameIDPolicy" minOccurs="0"/> */
	char *NameIDPolicy;
	/* <xs:element name="ForceAuthn" type="xs:boolean" minOccurs="0"/> */
	gboolean ForceAuthn;
	/* <xs:element name="IsPassive" type="xs:boolean "minOccurs="0"/> */
	gboolean IsPassive;
	/* <xs:element ref="ProtocolProfile" minOccurs="0"/> */
	char *ProtocolProfile;
	/* <xs:element name="AssertionConsumerServiceID" type="xs:string" minOccurs="0"/> */
	char *AssertionConsumerServiceID;
	/* <xs:element ref="RequestAuthnContext" minOccurs="0"/> */
	LassoLibRequestAuthnContext *RequestAuthnContext;
	/* <xs:element ref="RelayState" minOccurs="0"/> */
	char *RelayState;
	/* <xs:element ref="Scoping" minOccurs="0 "/> */
	LassoLibScoping *Scoping;
	/* <xs:attribute ref="consent" use="optional"/> */
	char *consent;
};

struct _LassoLibAuthnRequestClass {
	LassoSamlpRequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_lib_authn_request_get_type(void);
LASSO_EXPORT LassoLibAuthnRequest* lasso_lib_authn_request_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_AUTHN_REQUEST_H__ */
