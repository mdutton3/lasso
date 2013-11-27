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

#ifndef __LASSO_SAML2_ATTRIBUTE_STATEMENT_H__
#define __LASSO_SAML2_ATTRIBUTE_STATEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "saml2_statement_abstract.h"

#define LASSO_TYPE_SAML2_ATTRIBUTE_STATEMENT (lasso_saml2_attribute_statement_get_type())
#define LASSO_SAML2_ATTRIBUTE_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML2_ATTRIBUTE_STATEMENT, \
				LassoSaml2AttributeStatement))
#define LASSO_SAML2_ATTRIBUTE_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML2_ATTRIBUTE_STATEMENT, \
				LassoSaml2AttributeStatementClass))
#define LASSO_IS_SAML2_ATTRIBUTE_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML2_ATTRIBUTE_STATEMENT))
#define LASSO_IS_SAML2_ATTRIBUTE_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML2_ATTRIBUTE_STATEMENT))
#define LASSO_SAML2_ATTRIBUTE_STATEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML2_ATTRIBUTE_STATEMENT, \
				LassoSaml2AttributeStatementClass))

typedef struct _LassoSaml2AttributeStatement LassoSaml2AttributeStatement;
typedef struct _LassoSaml2AttributeStatementClass LassoSaml2AttributeStatementClass;


struct _LassoSaml2AttributeStatement {
	LassoSaml2StatementAbstract parent;

	/*< public >*/
	/* elements */
	GList *Attribute; /* of LassoSaml2Attribute */
	GList *EncryptedAttribute; /* of LassoSaml2EncryptedElement */
};


struct _LassoSaml2AttributeStatementClass {
	LassoSaml2StatementAbstractClass parent;
};

LASSO_EXPORT GType lasso_saml2_attribute_statement_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml2_attribute_statement_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML2_ATTRIBUTE_STATEMENT_H__ */
