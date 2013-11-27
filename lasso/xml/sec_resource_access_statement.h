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

#ifndef __LASSO_SEC_RESOURCE_ACCESS_STATEMENT_H__
#define __LASSO_SEC_RESOURCE_ACCESS_STATEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "saml_subject_statement_abstract.h"

#define LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT (lasso_sec_resource_access_statement_get_type())
#define LASSO_SEC_RESOURCE_ACCESS_STATEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT, \
		LassoSecResourceAccessStatement))
#define LASSO_SEC_RESOURCE_ACCESS_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT, \
		LassoSecResourceAccessStatementClass))
#define LASSO_IS_SEC_RESOURCE_ACCESS_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT))
#define LASSO_IS_SEC_RESOURCE_ACCESS_STATEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT))
#define LASSO_SEC_RESOURCE_ACCESS_STATEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SEC_RESOURCE_ACCESS_STATEMENT, \
		LassoSecResourceAccessStatementClass))

typedef struct _LassoSecResourceAccessStatement LassoSecResourceAccessStatement;
typedef struct _LassoSecResourceAccessStatementClass LassoSecResourceAccessStatementClass;

struct _LassoSecResourceAccessStatement {
	LassoSamlSubjectStatementAbstract parent;

	/*< public >*/
};

struct _LassoSecResourceAccessStatementClass {
	LassoSamlSubjectStatementAbstractClass parent;
};

LASSO_EXPORT GType lasso_sec_resource_access_statement_get_type(void);
LASSO_EXPORT LassoNode* lasso_sec_resource_access_statement_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SEC_RESOURCE_ACCESS_STATEMENT_H__ */
