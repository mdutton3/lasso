/* $Id
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

#ifndef __LASSO_DS_RSA_KEY_VALUE_H__
#define __LASSO_DS_RSA_KEY_VALUE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_DS_RSA_KEY_VALUE (lasso_ds_rsa_key_value_get_type())
#define LASSO_DS_RSA_KEY_VALUE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DS_RSA_KEY_VALUE, \
				    LassoDsRsaKeyValue))
#define LASSO_DS_RSA_KEY_VALUE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DS_RSA_KEY_VALUE, \
				 LassoDsRsaKeyValueClass))
#define LASSO_IS_DS_RSA_KEY_VALUE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DS_RSA_KEY_VALUE))
#define LASSO_IS_DS_RSA_KEY_VALUE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DS_RSA_KEY_VALUE))
#define LASSO_DS_RSA_KEY_VALUE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DS_RSA_KEY_VALUE, \
				    LassoDsRsaKeyValueClass))

typedef struct _LassoDsRsaKeyValue LassoDsRsaKeyValue;
typedef struct _LassoDsRsaKeyValueClass LassoDsRsaKeyValueClass;

struct _LassoDsRsaKeyValue {
	LassoNode parent;

	char *Modulus;
	char *Exponent;
};

struct _LassoDsRsaKeyValueClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_ds_rsa_key_value_get_type(void);
LASSO_EXPORT LassoDsRsaKeyValue* lasso_ds_rsa_key_value_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DS_RSA_KEY_VALUE_H__ */
