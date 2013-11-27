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

#include "identity.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "../utils.h"
#include "../id-ff/identity.h"
#include "../id-ff/identityprivate.h"

gint
lasso_identity_add_svc_md_id(LassoIdentity *identity, gchar *svcMDID)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(svcMDID != NULL, LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

	lasso_list_add_string(identity->private_data->svcMDID, svcMDID);
	identity->is_dirty = TRUE;

	return 0;
}

/**
 * lasso_identity_get_svc_md_ids:
 * @identity: a #LassoIdentity object
 *
 * Return value:(element-type string): a list of all collected svcMDIDs
 */
GList*
lasso_identity_get_svc_md_ids(LassoIdentity *identity)
{
	g_return_val_if_fail(LASSO_IS_IDENTITY(identity), NULL);

	return identity->private_data->svcMDID;
}
