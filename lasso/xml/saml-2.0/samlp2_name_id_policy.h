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

#ifndef __LASSO_SAMLP2_NAME_ID_POLICY_H__
#define __LASSO_SAMLP2_NAME_ID_POLICY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_SAMLP2_NAME_ID_POLICY (lasso_samlp2_name_id_policy_get_type())
#define LASSO_SAMLP2_NAME_ID_POLICY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_NAME_ID_POLICY, \
				LassoSamlp2NameIDPolicy))
#define LASSO_SAMLP2_NAME_ID_POLICY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_NAME_ID_POLICY, \
				LassoSamlp2NameIDPolicyClass))
#define LASSO_IS_SAMLP2_NAME_ID_POLICY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_NAME_ID_POLICY))
#define LASSO_IS_SAMLP2_NAME_ID_POLICY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_NAME_ID_POLICY))
#define LASSO_SAMLP2_NAME_ID_POLICY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_NAME_ID_POLICY, \
				LassoSamlp2NameIDPolicyClass))

typedef struct _LassoSamlp2NameIDPolicy LassoSamlp2NameIDPolicy;
typedef struct _LassoSamlp2NameIDPolicyClass LassoSamlp2NameIDPolicyClass;

/**
 * LassoSamlp2NameIDPolicy:
 * @Format: the name-identifier format, see #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_EMAIL,
 * #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_X509, #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_WINDOWS,
 * #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS, #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY,
 * #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT, #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT or
 * #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED.
 * @SPNameQualifier: other providerID to use as SPNameQualifier in the returned assertion. By
 * default an IdP create a NameID for the requesting entity, this field allows to obtain a NameID
 * qualified for a third party.
 * @AllowCreate: authorize the identity provider to create a new federation, otherwise it must
 * report a failure in case no existing federation is found (status code of
 * #LASSO_LIB_STATUS_CODE_FEDERATION_DOES_NOT_EXIST and error code of
 * #LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND).
 *
 * NameIDPolicy element is part of AuthnRequest and allows to give hint to the identity provider
 * about the NameID the service provider desire to receive.
 */
struct _LassoSamlp2NameIDPolicy {
	LassoNode parent;

	/*< public >*/
	/* attributes */
	char *Format;
	char *SPNameQualifier;
	gboolean AllowCreate;
};


struct _LassoSamlp2NameIDPolicyClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_samlp2_name_id_policy_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_name_id_policy_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_NAME_ID_POLICY_H__ */
