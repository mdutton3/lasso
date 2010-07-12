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

#ifndef __LASSO_WSF_ID_FF_EXTENSIONS_H__
#define __LASSO_WSF_ID_FF_EXTENSIONS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/login.h"
#include "../id-ff/server.h"
#include "../xml/disco_encrypted_resource_id.h"
#include "../xml/disco_service_instance.h"
#include "../xml/disco_resource_offering.h"

LASSO_EXPORT lasso_error_t lasso_login_set_encryptedResourceId(
		LassoLogin *login, LassoDiscoEncryptedResourceID *encryptedResourceId);

LASSO_EXPORT lasso_error_t lasso_login_set_resourceId(LassoLogin *login, const char *content);

LASSO_EXPORT LassoDiscoServiceInstance* lasso_server_get_service(LassoServer *server,
		const gchar *serviceType);

LASSO_EXPORT lasso_error_t lasso_server_add_service(LassoServer *server, LassoNode *service);

LASSO_EXPORT lasso_error_t lasso_server_add_service_from_dump(LassoServer *server, const gchar *dump);

LASSO_EXPORT lasso_error_t lasso_identity_add_resource_offering(LassoIdentity *identity,
		LassoDiscoResourceOffering *offering);
LASSO_EXPORT gboolean lasso_identity_remove_resource_offering(LassoIdentity *identity,
		const char *entryID);
LASSO_EXPORT GList* lasso_identity_get_offerings(LassoIdentity *identity,
		const char *service_type);
LASSO_EXPORT LassoDiscoResourceOffering* lasso_identity_get_resource_offering(
		LassoIdentity *identity, const char *entryID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSF_ID_FF_EXTENSIONS_H__ */
