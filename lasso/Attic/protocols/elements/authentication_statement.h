/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_AUTHENTICATION_STATEMENT_H__
#define __LASSO_AUTHENTICATION_STATEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/lib_authentication_statement.h>

#define LASSO_TYPE_AUTHENTICATION_STATEMENT (lasso_authentication_statement_get_type())
#define LASSO_AUTHENTICATION_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_AUTHENTICATION_STATEMENT, LassoAuthenticationStatement))
#define LASSO_AUTHENTICATION_STATEMENT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_AUTHENTICATION_STATEMENT, LassoAuthenticationStatementClass))
#define LASSO_IS_AUTHENTICATION_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_AUTHENTICATION_STATEMENT))
#define LASSO_IS_AUTHENTICATION_STATEMENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_AUTHENTICATION_STATEMENT))
#define LASSO_AUTHENTICATION_STATEMENT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_AUTHENTICATION_STATEMENT, LassoAuthenticationStatementClass)) 

typedef struct _LassoAuthenticationStatement LassoAuthenticationStatement;
typedef struct _LassoAuthenticationStatementClass LassoAuthenticationStatementClass;

struct _LassoAuthenticationStatement {
  LassoLibAuthenticationStatement parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoAuthenticationStatementClass {
  LassoLibAuthenticationStatementClass parent;
};

LASSO_EXPORT GType      lasso_authentication_statement_get_type (void);
LASSO_EXPORT LassoNode* lasso_authentication_statement_new      (const xmlChar           *authenticationMethod,
								 const xmlChar           *reauthenticateOnOrAfter,
								 LassoSamlNameIdentifier *identifier,
								 LassoSamlNameIdentifier *idp_identifier);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_AUTHENTICATION_STATEMENT_H__ */
