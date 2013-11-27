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

#ifndef __LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST_H__
#define __LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp2_request_abstract.h"
#include "samlp2_terminate.h"
#include "saml2_encrypted_element.h"
#include "saml2_name_id.h"

#define LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST (lasso_samlp2_manage_name_id_request_get_type())
#define LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST, \
				LassoSamlp2ManageNameIDRequest))
#define LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST, \
				LassoSamlp2ManageNameIDRequestClass))
#define LASSO_IS_SAMLP2_MANAGE_NAME_ID_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST))
#define LASSO_IS_SAMLP2_MANAGE_NAME_ID_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST))
#define LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_MANAGE_NAME_ID_REQUEST, \
				LassoSamlp2ManageNameIDRequestClass))

typedef struct _LassoSamlp2ManageNameIDRequest LassoSamlp2ManageNameIDRequest;
typedef struct _LassoSamlp2ManageNameIDRequestClass LassoSamlp2ManageNameIDRequestClass;


struct _LassoSamlp2ManageNameIDRequest {
	LassoSamlp2RequestAbstract parent;

	/*< public >*/
	/* elements */
	LassoSaml2NameID *NameID;
	LassoSaml2EncryptedElement *EncryptedID;
	char *NewID;
	LassoSaml2EncryptedElement *NewEncryptedID;
	LassoSamlp2Terminate *Terminate;
};


struct _LassoSamlp2ManageNameIDRequestClass {
	LassoSamlp2RequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_samlp2_manage_name_id_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_manage_name_id_request_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST_H__ */
