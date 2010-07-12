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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __LASSO_NAME_IDENTIFIER_MAPPING_H__
#define __LASSO_NAME_IDENTIFIER_MAPPING_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "profile.h"

#include "../xml/lib_name_identifier_mapping_request.h"
#include "../xml/lib_name_identifier_mapping_response.h"

#define LASSO_TYPE_NAME_IDENTIFIER_MAPPING (lasso_name_identifier_mapping_get_type())
#define LASSO_NAME_IDENTIFIER_MAPPING(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING, \
				    LassoNameIdentifierMapping))
#define LASSO_NAME_IDENTIFIER_MAPPING_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING, \
				 LassoNameIdentifierMappingClass))
#define LASSO_IS_NAME_IDENTIFIER_MAPPING(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING))
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING))
#define LASSO_NAME_IDENTIFIER_MAPPING_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NAME_IDENTIFIER_MAPPING, \
				    LassoNameIdentifierMappingClass))

typedef struct _LassoNameIdentifierMapping LassoNameIdentifierMapping;
typedef struct _LassoNameIdentifierMappingClass LassoNameIdentifierMappingClass;

struct _LassoNameIdentifierMapping {
	LassoProfile parent;

	/*< public >*/
	gchar *targetNameIdentifier;

	/*< private >*/
	void *private_data;  /* reserved for future use */
};

struct _LassoNameIdentifierMappingClass {
	LassoProfileClass parent;
};

LASSO_EXPORT GType lasso_name_identifier_mapping_get_type(void);

LASSO_EXPORT LassoNameIdentifierMapping* lasso_name_identifier_mapping_new(LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_name_identifier_mapping_build_request_msg(
		LassoNameIdentifierMapping *mapping);

LASSO_EXPORT lasso_error_t lasso_name_identifier_mapping_build_response_msg(
		LassoNameIdentifierMapping *mapping);

LASSO_EXPORT void lasso_name_identifier_mapping_destroy(
		LassoNameIdentifierMapping *mapping);

LASSO_EXPORT lasso_error_t lasso_name_identifier_mapping_init_request(
		LassoNameIdentifierMapping *mapping,
		gchar *targetNamespace, gchar *remote_providerID);

LASSO_EXPORT lasso_error_t lasso_name_identifier_mapping_process_request_msg(
		LassoNameIdentifierMapping *mapping, gchar *request_msg);

LASSO_EXPORT lasso_error_t lasso_name_identifier_mapping_process_response_msg(
		LassoNameIdentifierMapping *mapping, gchar *response_msg);

LASSO_EXPORT lasso_error_t lasso_name_identifier_mapping_validate_request(
		LassoNameIdentifierMapping *mapping);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_NAME_IDENTIFIER_MAPPING_H__ */
