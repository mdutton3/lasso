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

#ifndef __LASSO_IDENTITY_PRIVATE_H__
#define __LASSO_IDENTITY_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "config.h"

struct _LassoIdentityPrivate
{
	gboolean dispose_has_run;
#ifdef LASSO_WSF_ENABLED
	guint last_entry_id;
	GHashTable *resource_offerings_map; /* of LassoDiscoResourceOffering */
	GList *svcMDID; /* of char* */
#endif
};

gint lasso_identity_add_federation(LassoIdentity *identity, LassoFederation *federation);
gint lasso_identity_remove_federation(LassoIdentity *identity, const char *providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDENTITY_PRIVATE_H__ */
