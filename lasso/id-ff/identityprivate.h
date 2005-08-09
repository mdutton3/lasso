/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

gint lasso_identity_add_federation(LassoIdentity *identity, LassoFederation *federation);
gint lasso_identity_remove_federation(LassoIdentity *identity, const char *providerID);

#ifdef LASSO_WSF_ENABLED
#include <lasso/xml/disco_resource_offering.h>
gint lasso_identity_add_resource_offering(LassoIdentity *identity,
		LassoDiscoResourceOffering *offering);
gboolean lasso_identity_remove_resource_offering(LassoIdentity *identity, const char *entryID);
GList* lasso_identity_get_offerings(LassoIdentity *identity, const char *service_type);
#endif


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDENTITY_PRIVATE_H__ */
