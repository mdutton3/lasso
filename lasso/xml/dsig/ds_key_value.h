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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_DS_KEY_VALUE_H__
#define __LASSO_DS_KEY_VALUE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "ds_rsa_key_value.h"
#include "ds_x509_data.h"

#define LASSO_TYPE_DS_KEY_VALUE (lasso_ds_key_value_get_type())
#define LASSO_DS_KEY_VALUE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DS_KEY_VALUE, \
				    LassoDsKeyValue))
#define LASSO_DS_KEY_VALUE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DS_KEY_VALUE, \
				 LassoDsKeyValueClass))
#define LASSO_IS_DS_KEY_VALUE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DS_KEY_VALUE))
#define LASSO_IS_DS_KEY_VALUE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DS_KEY_VALUE))
#define LASSO_DS_KEY_VALUE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DS_KEY_VALUE, \
				    LassoDsKeyValueClass))

typedef struct _LassoDsKeyValue LassoDsKeyValue;
typedef struct _LassoDsKeyValueClass LassoDsKeyValueClass;

struct _LassoDsKeyValue {
	LassoNode parent;

	LassoDsRsaKeyValue *RSAKeyValue;
};

struct _LassoDsKeyValueClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_ds_key_value_get_type(void);
LASSO_EXPORT LassoDsKeyValue* lasso_ds_key_value_new(void);
LASSO_EXPORT LassoDsX509Data *lasso_ds_key_value_get_x509_data(LassoDsKeyValue *key_value);
LASSO_EXPORT void lasso_ds_key_value_set_x509_data(LassoDsKeyValue *key_value, LassoDsX509Data
		*x509_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DS_KEY_VALUE_H__ */
