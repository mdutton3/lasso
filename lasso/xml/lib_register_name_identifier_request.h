/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_H__
#define __LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/samlp_request_abstract.h>
#include <lasso/xml/lib_idp_provided_name_identifier.h>
#include <lasso/xml/lib_old_provided_name_identifier.h>
#include <lasso/xml/lib_sp_provided_name_identifier.h>

#define LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST (lasso_lib_register_name_identifier_request_get_type())
#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, LassoLibRegisterNameIdentifierRequest))
#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, LassoLibRegisterNameIdentifierRequestClass))
#define LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST))
#define LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST))
#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, LassoLibRegisterNameIdentifierRequestClass)) 

typedef struct _LassoLibRegisterNameIdentifierRequest LassoLibRegisterNameIdentifierRequest;
typedef struct _LassoLibRegisterNameIdentifierRequestClass LassoLibRegisterNameIdentifierRequestClass;

struct _LassoLibRegisterNameIdentifierRequest {
  LassoSamlpRequestAbstract parent;
  /*< private >*/
};

struct _LassoLibRegisterNameIdentifierRequestClass {
  LassoSamlpRequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_lib_register_name_identifier_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_lib_register_name_identifier_request_new(void);

LASSO_EXPORT void lasso_lib_register_name_identifier_request_set_relayState                (LassoLibRegisterNameIdentifierRequest *,
											    const xmlChar *);

LASSO_EXPORT void lasso_lib_register_name_identifier_request_set_providerID                (LassoLibRegisterNameIdentifierRequest *,
											    const xmlChar *);

LASSO_EXPORT void lasso_lib_register_name_identifier_request_set_idpProvidedNameIdentifier (LassoLibRegisterNameIdentifierRequest *,
											    LassoLibIDPProvidedNameIdentifier *);

LASSO_EXPORT void lasso_lib_register_name_identifier_request_set_oldProvidedNameIdentifier (LassoLibRegisterNameIdentifierRequest *,
											    LassoLibOLDProvidedNameIdentifier *);

LASSO_EXPORT void lasso_lib_register_name_identifier_request_set_spProvidedNameIdentifier  (LassoLibRegisterNameIdentifierRequest *,
											    LassoLibSPProvidedNameIdentifier *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_H__ */
