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

#ifndef __LASSO_DS_SIGNATURE_H__
#define __LASSO_DS_SIGNATURE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_DS_SIGNATURE (lasso_ds_signature_get_type())
#define LASSO_DS_SIGNATURE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DS_SIGNATURE, LassoDsSignature))
#define LASSO_DS_SIGNATURE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DS_SIGNATURE, LassoDsSignatureClass))
#define LASSO_IS_DS_SIGNATURE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DS_SIGNATURE))
#define LASSO_IS_DS_SIGNATURE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DS_SIGNATURE))
#define LASSO_DS_SIGNATURE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DS_SIGNATURE, LassoDsSignatureClass)) 

typedef struct _LassoDsSignature LassoDsSignature;
typedef struct _LassoDsSignatureClass LassoDsSignatureClass;

struct _LassoDsSignature {
  LassoNode parent;
  /*< private >*/
};

struct _LassoDsSignatureClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_ds_signature_get_type(void);
LASSO_EXPORT LassoNode* lasso_ds_signature_new(LassoNode        *node,
					       xmlSecTransformId sign_method);

LASSO_EXPORT gint lasso_ds_signature_sign (LassoDsSignature *node,
					   const xmlChar    *private_key_file,
					   const xmlChar    *certificate_file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DS_SIGNATURE_H__ */
