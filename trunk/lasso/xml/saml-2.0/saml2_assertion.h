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

#ifndef __LASSO_SAML2_ASSERTION_H__
#define __LASSO_SAML2_ASSERTION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#define LASSO_TYPE_SAML2_ASSERTION (lasso_saml2_assertion_get_type())
#define LASSO_SAML2_ASSERTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML2_ASSERTION, \
				LassoSaml2Assertion))
#define LASSO_SAML2_ASSERTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML2_ASSERTION, \
				LassoSaml2AssertionClass))
#define LASSO_IS_SAML2_ASSERTION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML2_ASSERTION))
#define LASSO_IS_SAML2_ASSERTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML2_ASSERTION))
#define LASSO_SAML2_ASSERTION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML2_ASSERTION, \
				LassoSaml2AssertionClass))

typedef struct _LassoSaml2Assertion LassoSaml2Assertion;
typedef struct _LassoSaml2AssertionClass LassoSaml2AssertionClass;

#include "saml2_advice.h"
#include "saml2_conditions.h"
#include "saml2_subject.h"
#include "saml2_name_id.h"

#include "../xml_enc.h"

struct _LassoSaml2Assertion {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoSaml2NameID *Issuer;
	LassoSaml2Subject *Subject;
	LassoSaml2Conditions *Conditions;
	LassoSaml2Advice *Advice;
	GList *Statement; /* of LassoSaml2StatementAbstract */
	GList *AuthnStatement; /* of LassoSaml2AuthnStatement */
	GList *AuthzDecisionStatement; /* of LassoSaml2AuthzDecisionStatement */
	GList *AttributeStatement; /* of LassoSaml2AttributeStatement */
	/* attributes */
	char *Version;
	char *ID;
	char *IssueInstant;
	/*< private >*/
	/* ds:Signature stuffs */
	LassoSignatureType sign_type;
	LassoSignatureMethod sign_method;
	char *private_key_file;
	char *certificate_file;
	gboolean encryption_activated;
	char *encryption_public_key_str;
	LassoEncryptionSymKeyType encryption_sym_key_type;
};


struct _LassoSaml2AssertionClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml2_assertion_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml2_assertion_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML2_ASSERTION_H__ */
