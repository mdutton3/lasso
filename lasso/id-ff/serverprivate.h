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

#ifndef __LASSO_SERVER_PRIVATE_H__
#define __LASSO_SERVER_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _LassoServerPrivate
{
	gboolean dispose_has_run;
	xmlSecKey *encryption_private_key;
	GList *svc_metadatas;
};

gchar* lasso_server_get_first_providerID(LassoServer *server);
gchar* lasso_server_get_first_providerID_by_role(const LassoServer *server, LassoProviderRole role);
gchar* lasso_server_get_providerID_from_hash(LassoServer *server, gchar *b64_hash);
xmlSecKey* lasso_server_get_private_key(LassoServer *server);
xmlSecKey* lasso_server_get_encryption_private_key(LassoServer *server);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SERVER_PRIVATE_H__ */
