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

#ifndef __LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_H__
#define __LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "../dsig/ds_key_info.h"
#include "saml2_subject_confirmation_data.h"

#define LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE \
	(lasso_saml2_key_info_confirmation_data_type_get_type())
#define LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE, \
				LassoSaml2KeyInfoConfirmationDataType))
#define LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE, \
				LassoSaml2KeyInfoConfirmationDataTypeClass))
#define LASSO_IS_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE))
#define LASSO_IS_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE))
#define LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE, \
				LassoSaml2KeyInfoConfirmationDataTypeClass))

typedef struct _LassoSaml2KeyInfoConfirmationDataType LassoSaml2KeyInfoConfirmationDataType;
typedef struct _LassoSaml2KeyInfoConfirmationDataTypeClass LassoSaml2KeyInfoConfirmationDataTypeClass;
typedef struct _LassoSaml2KeyInfoConfirmationDataTypePrivate LassoSaml2KeyInfoConfirmationDataTypePrivate;

struct _LassoSaml2KeyInfoConfirmationDataType {
	LassoSaml2SubjectConfirmationData parent;

	/*< private >*/
	LassoSaml2KeyInfoConfirmationDataTypePrivate *private_data;
};


struct _LassoSaml2KeyInfoConfirmationDataTypeClass {
	LassoSaml2SubjectConfirmationDataClass parent;
};

LASSO_EXPORT GType lasso_saml2_key_info_confirmation_data_type_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml2_key_info_confirmation_data_type_new(void);
LASSO_EXPORT GList *lasso_saml2_key_info_confirmation_data_type_get_key_info(
		LassoSaml2KeyInfoConfirmationDataType *kicdt);
LASSO_EXPORT void lasso_saml2_key_info_confirmation_data_type_set_key_info(
		LassoSaml2KeyInfoConfirmationDataType *kicdt,
		GList *key_infos);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML2_KEY_INFO_CONFIRMATION_DATA_TYPE_H__ */
