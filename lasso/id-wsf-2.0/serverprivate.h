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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_IDWSF2_SERVERPRIVATE_H__
#define __LASSO_IDWSF2_SERVERPRIVATE_H__

#include "../utils.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/server.h"
#include <libxml/tree.h>

void lasso_server_init_id_wsf20_svcmds(LassoServer *server, xmlNode *t);

void lasso_server_dump_id_wsf20_svcmds(LassoServer *server, xmlNode *xmlnode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SERVERPRIVATE_H__ */
