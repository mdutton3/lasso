/* $Id: identity.h 2633 2005-09-05 10:00:07Z dlaniel $
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2007 Entr'ouvert
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

#ifndef __LASSO_IDWSF2_IDENTITY_H__
#define __LASSO_IDWSF2_IDENTITY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/id-wsf-2.0/disco_svc_metadata.h>
#include <lasso/xml/id-wsf-2.0/disco_service_type.h>
#include <lasso/xml/ws/wsa_endpoint_reference.h>

LASSO_EXPORT gint lasso_identity_add_svc_metadata(LassoIdentity *identity,
        LassoIdWsf2DiscoSvcMetadata *metadata);

LASSO_EXPORT GList* lasso_identity_get_svc_metadatas(LassoIdentity *identity,
        const char *service_type);

LASSO_EXPORT gint lasso_identity_add_endpoint_reference(LassoIdentity *identity,
        LassoWsAddrEndpointReference *epr);

LASSO_EXPORT LassoWsAddrEndpointReference *lasso_identity_get_endpoint_reference(
        LassoIdentity *identity, gchar *service_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_IDENTITY_H__ */
