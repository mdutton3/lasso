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

#ifndef __LASSO_SAML2_ENCRYPTED_ELEMENT_H__
#define __LASSO_SAML2_ENCRYPTED_ELEMENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include <xmlsec/xmlsec.h>

#define LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT (lasso_saml2_encrypted_element_get_type())
#define LASSO_SAML2_ENCRYPTED_ELEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT, \
				LassoSaml2EncryptedElement))
#define LASSO_SAML2_ENCRYPTED_ELEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT, \
				LassoSaml2EncryptedElementClass))
#define LASSO_IS_SAML2_ENCRYPTED_ELEMENT(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT))
#define LASSO_IS_SAML2_ENCRYPTED_ELEMENT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT))
#define LASSO_SAML2_ENCRYPTED_ELEMENT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML2_ENCRYPTED_ELEMENT, \
				LassoSaml2EncryptedElementClass))

typedef struct _LassoSaml2EncryptedElement LassoSaml2EncryptedElement;
typedef struct _LassoSaml2EncryptedElementClass LassoSaml2EncryptedElementClass;


struct _LassoSaml2EncryptedElement {
	LassoNode parent;

	/*< public >*/
	/* elements */
	xmlNode *EncryptedData;
	GList *EncryptedKey; /* of xmlNode* */
	LassoNode *original_data;
};


struct _LassoSaml2EncryptedElementClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml2_encrypted_element_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml2_encrypted_element_new(void);
LASSO_EXPORT lasso_error_t lasso_saml2_encrypted_element_decrypt(LassoSaml2EncryptedElement* encrypted_element, xmlSecKey *encryption_private_key, LassoNode** decrypted_node);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML2_ENCRYPTED_ELEMENT_H__ */
