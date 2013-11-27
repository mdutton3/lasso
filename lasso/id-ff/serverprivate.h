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

#ifndef __LASSO_SERVER_PRIVATE_H__
#define __LASSO_SERVER_PRIVATE_H__

#include "server.h"
#include "../xml/private.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


struct _LassoServerPrivate
{
	gboolean dispose_has_run;
	GList *encryption_private_keys;
	GList *svc_metadatas;
};

gchar* lasso_server_get_first_providerID(LassoServer *server);
gchar* lasso_server_get_first_providerID_by_role(const LassoServer *server, LassoProviderRole role);
gchar* lasso_server_get_providerID_from_hash(LassoServer *server, gchar *b64_hash);
xmlSecKey* lasso_server_get_private_key(LassoServer *server);
GList* lasso_server_get_encryption_private_keys(LassoServer *server);

lasso_error_t lasso_server_get_signature_context_for_provider(LassoServer *server,
		LassoProvider *provider, LassoSignatureContext *signature_context);

lasso_error_t lasso_server_get_signature_context_for_provider_by_name(LassoServer *server,
		const char *provider_id, LassoSignatureContext *signature_context);

lasso_error_t lasso_server_set_signature_for_provider_by_name(LassoServer *server,
		const char *provider_id, LassoNode *node);

lasso_error_t lasso_server_export_to_query_for_provider_by_name(LassoServer *server,
		const char *provider_id, LassoNode *node, char **query);

lasso_error_t lasso_server_get_signature_context(LassoServer *server, LassoSignatureContext
		*context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SERVER_PRIVATE_H__ */
