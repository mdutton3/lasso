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

#ifndef __LASSO_SAML_ASSERTION_H__
#define __LASSO_SAML_ASSERTION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "saml_advice.h"
#include "saml_authentication_statement.h"
#include "saml_conditions.h"
#include "saml_statement_abstract.h"
#include "saml_subject_statement.h"
#include "saml_attribute_statement.h"

#define LASSO_TYPE_SAML_ASSERTION (lasso_saml_assertion_get_type())
#define LASSO_SAML_ASSERTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_ASSERTION, LassoSamlAssertion))
#define LASSO_SAML_ASSERTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_ASSERTION, LassoSamlAssertionClass))
#define LASSO_IS_SAML_ASSERTION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_ASSERTION))
#define LASSO_IS_SAML_ASSERTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_ASSERTION))
#define LASSO_SAML_ASSERTION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_ASSERTION, LassoSamlAssertionClass))

typedef struct _LassoSamlAssertion LassoSamlAssertion;
typedef struct _LassoSamlAssertionClass LassoSamlAssertionClass;

struct _LassoSamlAssertion {
	LassoNode parent;

	/*< public >*/
	/* <element ref="saml:Conditions" minOccurs="0"/> */
	LassoSamlConditions *Conditions;
	/* <element ref="saml:Advice" minOccurs="0"/> */
	LassoSamlAdvice *Advice;
	void *Statement; /* XXX LassoSamlStatement missing from lasso */
	LassoSamlSubjectStatement *SubjectStatement;
	LassoSamlAuthenticationStatement *AuthenticationStatement;
	void *AuthorizationDecisionStatement;
		/* XXX LassoSamlAuthorizationDecisionStatement missing from lasso*/
	LassoSamlAttributeStatement *AttributeStatement;

	int MajorVersion;
	int MinorVersion;
	char *AssertionID;
	char *Issuer;
	char *IssueInstant;

	/* ds:Signature stuff */
	LassoSignatureType sign_type;
	LassoSignatureMethod sign_method;
	char *private_key_file;
	char *certificate_file;
};

struct _LassoSamlAssertionClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml_assertion_get_type(void);
LASSO_EXPORT LassoSamlAssertion* lasso_saml_assertion_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_ASSERTION_H__ */
