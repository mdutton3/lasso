/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#ifndef __LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_H__
#define __LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/lib_register_name_identifier_request.h>

#define LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST (lasso_register_name_identifier_request_get_type())
#define LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, LassoRegisterNameIdentifierRequest))
#define LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, LassoRegisterNameIdentifierRequestClass))
#define LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST))
#define LASSP_IS_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST))
#define LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, LassoRegisterNameIdentifierRequestClass)) 

typedef struct _LassoRegisterNameIdentifierRequest LassoRegisterNameIdentifierRequest;
typedef struct _LassoRegisterNameIdentifierRequestClass LassoRegisterNameIdentifierRequestClass;

struct _LassoRegisterNameIdentifierRequest {
  LassoLibRegisterNameIdentifierRequest parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoRegisterNameIdentifierRequestClass {
  LassoLibRegisterNameIdentifierRequestClass parent;
};

LASSO_EXPORT GType      lasso_register_name_identifier_request_get_type (void);

LASSO_EXPORT LassoNode* lasso_register_name_identifier_request_new            (const xmlChar     *providerID,
									       const xmlChar     *idpProvidedNameIdentifier,
									       const xmlChar     *idpNameQualifier,
									       const xmlChar     *idpFormat,
									       const xmlChar     *spProvidedNameIdentifier,
									       const xmlChar     *spNameQualifier,
									       const xmlChar     *spFormat,
									       const xmlChar     *oldProvidedNameIdentifier,
									       const xmlChar     *oldNameQualifier,
									       const xmlChar     *oldFormat);

LASSO_EXPORT LassoNode* lasso_register_name_identifier_request_new_from_query (const xmlChar *query);
LASSO_EXPORT LassoNode* lasso_register_name_identifier_request_new_from_soap  (const xmlChar *buffer);


LASSO_EXPORT void lasso_register_name_identifier_rename_attributes_for_query(LassoRegisterNameIdentifierRequest *request);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_H__ */
