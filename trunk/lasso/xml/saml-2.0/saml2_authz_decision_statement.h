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

#ifndef __LASSO_SAML2_AUTHZ_DECISION_STATEMENT_H__
#define __LASSO_SAML2_AUTHZ_DECISION_STATEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "saml2_action.h"
#include "saml2_evidence.h"
#include "saml2_statement_abstract.h"

#define LASSO_TYPE_SAML2_AUTHZ_DECISION_STATEMENT (lasso_saml2_authz_decision_statement_get_type())
#define LASSO_SAML2_AUTHZ_DECISION_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML2_AUTHZ_DECISION_STATEMENT, \
				LassoSaml2AuthzDecisionStatement))
#define LASSO_SAML2_AUTHZ_DECISION_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML2_AUTHZ_DECISION_STATEMENT, \
				LassoSaml2AuthzDecisionStatementClass))
#define LASSO_IS_SAML2_AUTHZ_DECISION_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML2_AUTHZ_DECISION_STATEMENT))
#define LASSO_IS_SAML2_AUTHZ_DECISION_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML2_AUTHZ_DECISION_STATEMENT))
#define LASSO_SAML2_AUTHZ_DECISION_STATEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML2_AUTHZ_DECISION_STATEMENT, \
				LassoSaml2AuthzDecisionStatementClass))

typedef struct _LassoSaml2AuthzDecisionStatement LassoSaml2AuthzDecisionStatement;
typedef struct _LassoSaml2AuthzDecisionStatementClass LassoSaml2AuthzDecisionStatementClass;


struct _LassoSaml2AuthzDecisionStatement {
	LassoSaml2StatementAbstract parent;

	/*< public >*/
	/* elements */
	LassoSaml2Action *Action;
	LassoSaml2Evidence *Evidence;
	/* attributes */
	char *Resource;
	char *Decision;
};


struct _LassoSaml2AuthzDecisionStatementClass {
	LassoSaml2StatementAbstractClass parent;
};

LASSO_EXPORT GType lasso_saml2_authz_decision_statement_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml2_authz_decision_statement_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML2_AUTHZ_DECISION_STATEMENT_H__ */
