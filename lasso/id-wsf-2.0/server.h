/* $Id: server.h 2945 2006-11-19 20:07:46Z dlaniel $
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

#ifndef __LASSO_IDWSF2_SERVER_H__
#define __LASSO_IDWSF2_SERVER_H__

#include "../utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/server.h"
#include "../xml/id-wsf-2.0/disco_svc_metadata.h"

LASSO_EXPORT lasso_error_t lasso_server_add_svc_metadata(LassoServer *server,
	LassoIdWsf2DiscoSvcMetadata *metadata);

LASSO_EXPORT const GList *lasso_server_get_svc_metadatas(LassoServer *server);

LASSO_EXPORT GList *lasso_server_get_svc_metadatas_with_id_and_type(LassoServer *server,
	GList *svcMDIDs, const gchar *service_type);

void lasso_server_init_id_wsf20_services(LassoServer *server, xmlNode *t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SERVER_H__ */

