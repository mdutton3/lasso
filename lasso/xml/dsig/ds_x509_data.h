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

#ifndef __LASSO_DS_X509_DATA_H__
#define __LASSO_DS_X509_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_DS_X509_DATA (lasso_ds_x509_data_get_type())
#define LASSO_DS_X509_DATA(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DS_X509_DATA, \
				    LassoDsX509Data))
#define LASSO_DS_X509_DATA_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DS_X509_DATA, \
				 LassoDsX509DataClass))
#define LASSO_IS_DS_X509_DATA(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DS_X509_DATA))
#define LASSO_IS_DS_X509_DATA_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DS_X509_DATA))
#define LASSO_DS_X509_DATA_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DS_X509_DATA, \
				    LassoDsX509DataClass))

typedef struct _LassoDsX509Data LassoDsX509Data;
typedef struct _LassoDsX509DataClass LassoDsX509DataClass;
typedef struct _LassoDsX509DataPrivate LassoDsX509DataPrivate;

struct _LassoDsX509Data {
	LassoNode parent;
	/*< private >*/
	LassoDsX509DataPrivate *private_data;
};

struct _LassoDsX509DataClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_ds_x509_data_get_type(void);
LASSO_EXPORT LassoDsX509Data* lasso_ds_x509_data_new(void);
LASSO_EXPORT const char *lasso_ds_x509_data_get_certificate(LassoDsX509Data *x509_data);
LASSO_EXPORT void lasso_ds_x509_data_set_certificate(LassoDsX509Data *x509_data, const char *certificate);
LASSO_EXPORT const char *lasso_ds_x509_data_get_subject_name(LassoDsX509Data *x509_data);
LASSO_EXPORT void lasso_ds_x509_data_set_subject_name(LassoDsX509Data *x509_data, const char *subject_name);
LASSO_EXPORT const char *lasso_ds_x509_data_get_crl(LassoDsX509Data *x509_data);
LASSO_EXPORT void lasso_ds_x509_data_set_crl(LassoDsX509Data *x509_data, const char *crl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DS_X509_DATA_H__ */
