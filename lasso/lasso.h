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

#ifndef __LASSO_H__
#define __LASSO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if (defined _MSC_VER || defined MINGW32)
#   include <windows.h>
#endif

#include <glib.h>
#include <glib-object.h>

#include "export.h"

#include "id-ff/defederation.h"
#include "id-ff/lecp.h"
#include "id-ff/login.h"
#include "id-ff/logout.h"
#include "id-ff/name_identifier_mapping.h"
#include "id-ff/name_registration.h"
#include "saml-2.0/name_id_management.h"
#include "saml-2.0/ecp.h"
#include "saml-2.0/assertion_query.h"
#include "saml-2.0/saml2_helper.h"
#include "saml-2.0/profile.h"

LASSO_EXPORT lasso_error_t lasso_init(void);
LASSO_EXPORT lasso_error_t lasso_shutdown(void);

/**
 * LassoCheckVersionMode:
 * @LASSO_CHECK_VERSION_EXACT: version should match exactly
 * @LASSO_CHECK_VERSIONABI_COMPATIBLE: version should be ABI compatible
 * @LASSO_CHECK_VERSION_NUMERIC: version should be at least that number
 *
 * Lasso library version check mode.
 **/
typedef enum {
	LASSO_CHECK_VERSION_EXACT = 0,
	LASSO_CHECK_VERSIONABI_COMPATIBLE,
	LASSO_CHECK_VERSION_NUMERIC
} LassoCheckVersionMode;


LASSO_EXPORT int lasso_check_version(
		int major, int minor, int subminor, LassoCheckVersionMode mode);

LASSO_EXPORT void lasso_set_flag(char *flag);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_H__ */
