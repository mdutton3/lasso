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

#ifndef __LASSO_SAML_AUTHENTICATION_STATEMENT_H__
#define __LASSO_SAML_AUTHENTICATION_STATEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "saml_authority_binding.h"
#include "saml_subject_locality.h"
#include "saml_subject_statement_abstract.h"

#define LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT (lasso_saml_authentication_statement_get_type())
#define LASSO_SAML_AUTHENTICATION_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT,\
				    LassoSamlAuthenticationStatement))
#define LASSO_SAML_AUTHENTICATION_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT, \
				 LassoSamlAuthenticationStatementClass))
#define LASSO_IS_SAML_AUTHENTICATION_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT))
#define LASSO_IS_SAML_AUTHENTICATION_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT))
#define LASSO_SAML_AUTHENTICATION_STATEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT, \
				    LassoSamlAuthenticationStatementClass))

typedef struct _LassoSamlAuthenticationStatement LassoSamlAuthenticationStatement;
typedef struct _LassoSamlAuthenticationStatementClass LassoSamlAuthenticationStatementClass;

struct _LassoSamlAuthenticationStatement {
	LassoSamlSubjectStatementAbstract parent;

	/*< public >*/
	/* <element ref="saml:SubjectLocality" minOccurs="0"/> */
	LassoSamlSubjectLocality *SubjectLocality;
	/* <element ref="saml:AuthorityBinding" minOccurs="0" maxOccurs="unbounded"/> */
	GList *AuthorityBinding; /* of LassoNode */
	/* <attribute name="AuthenticationMethod" type="anyURI" use="required"/> */
	char *AuthenticationMethod;
	/* <attribute name="AuthenticationInstant" type="dateTime" use="required"/> */
	char *AuthenticationInstant;
};

struct _LassoSamlAuthenticationStatementClass {
	LassoSamlSubjectStatementAbstractClass parent;
};

LASSO_EXPORT GType lasso_saml_authentication_statement_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml_authentication_statement_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_AUTHENTICATION_STATEMENT_H__ */
