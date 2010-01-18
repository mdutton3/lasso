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

#ifndef __LASSO_SAMLP2_NAME_ID_MAPPING_REQUEST_H__
#define __LASSO_SAMLP2_NAME_ID_MAPPING_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp2_request_abstract.h"
#include "saml2_encrypted_element.h"
#include "saml2_name_id.h"
#include "saml2_base_idabstract.h"
#include "samlp2_name_id_policy.h"

#define LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST (lasso_samlp2_name_id_mapping_request_get_type())
#define LASSO_SAMLP2_NAME_ID_MAPPING_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST, \
				LassoSamlp2NameIDMappingRequest))
#define LASSO_SAMLP2_NAME_ID_MAPPING_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST, \
				LassoSamlp2NameIDMappingRequestClass))
#define LASSO_IS_SAMLP2_NAME_ID_MAPPING_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST))
#define LASSO_IS_SAMLP2_NAME_ID_MAPPING_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST))
#define LASSO_SAMLP2_NAME_ID_MAPPING_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_NAME_ID_MAPPING_REQUEST, \
				LassoSamlp2NameIDMappingRequestClass))

typedef struct _LassoSamlp2NameIDMappingRequest LassoSamlp2NameIDMappingRequest;
typedef struct _LassoSamlp2NameIDMappingRequestClass LassoSamlp2NameIDMappingRequestClass;


struct _LassoSamlp2NameIDMappingRequest {
	LassoSamlp2RequestAbstract parent;

	/*< public >*/
	/* elements */
	LassoSaml2BaseIDAbstract *BaseID;
	LassoSaml2NameID *NameID;
	LassoSaml2EncryptedElement *EncryptedID;
	LassoSamlp2NameIDPolicy *NameIDPolicy;
};


struct _LassoSamlp2NameIDMappingRequestClass {
	LassoSamlp2RequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_samlp2_name_id_mapping_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_name_id_mapping_request_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_NAME_ID_MAPPING_REQUEST_H__ */
