/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#ifndef __LASSO_XML_ENC_H__
#define __LASSO_XML_ENC_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/xml/xml.h>
#include <lasso/xml/saml-2.0/saml2_encrypted_element.h>

/**
 * LassoEncryptionSymKeyType:
 * LASSO_ENCRYPTION_SYM_KEY_TYPE_DEFAULT : Default type (Aes 256)
 * LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_256 : Aes 256 bits key
 * LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_128 : Aes 128 bits key
 * LASSO_ENCRYPTION_SYM_KEY_TYPE_3DES : Triple DES 192 bits key
 *
 * Encryption symetric key type.
 **/
typedef enum {
	LASSO_ENCRYPTION_SYM_KEY_TYPE_DEFAULT,
	LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_256,
	LASSO_ENCRYPTION_SYM_KEY_TYPE_AES_128,
	LASSO_ENCRYPTION_SYM_KEY_TYPE_3DES
} LassoEncryptionSymKeyType;

LassoSaml2EncryptedElement* lasso_node_encrypt(LassoNode *lasso_node,
				xmlSecKey *encryption_public_key,
				LassoEncryptionSymKeyType encryption_sym_key_type);
LassoNode* lasso_node_decrypt(LassoSaml2EncryptedElement* encrypted_element,
				xmlSecKey *encryption_private_key);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_XML_H__ */
