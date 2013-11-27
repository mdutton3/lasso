/* $Id: wsf_profile.h,v 1.13 2006/11/14 17:07:30 Exp $
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

#ifndef __LASSO_IDWSF2_HELPER_H__
#define __LASSO_IDWSF2_HELPER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/ws/wsa_endpoint_reference.h"
#include "../xml/id-wsf-2.0/disco_security_context.h"
#include "profile.h"


const char* lasso_wsa_endpoint_reference_get_idwsf2_service_type(
		const LassoWsAddrEndpointReference *epr);

const char* lasso_wsa_endpoint_reference_get_idwsf2_provider_id(
		const LassoWsAddrEndpointReference *epr);

LassoIdWsf2DiscoSecurityContext*
	lasso_wsa_endpoint_reference_get_idwsf2_security_context_for_security_mechanism(
			const LassoWsAddrEndpointReference *epr,
			gboolean (*sech_mech_predicate)(const char *),
			const char *security_mech_id,
			gboolean create);

LassoNode* lasso_wsa_endpoint_reference_get_security_token (const LassoWsAddrEndpointReference *epr,
		gboolean (*sech_mech_predicate)(const char *), const char *security_mech_id);

LASSO_EXPORT LassoNode* lasso_wsa_endpoint_reference_get_target_identity_token(
		const LassoWsAddrEndpointReference *epr,
		gboolean (*sech_mech_predicate)(const char *), const char *security_mech_id);

LASSO_EXPORT LassoWsAddrEndpointReference* lasso_wsa_endpoint_reference_new_for_idwsf2_service(
		const char *address, const char *service_ype, const char *provider_id,
		const char *abstract);

LASSO_EXPORT lasso_error_t lasso_wsa_endpoint_reference_add_security_token(LassoWsAddrEndpointReference *epr,
		LassoNode *security_token, GList *security_mechanisms);

LASSO_EXPORT LassoIdWsf2Profile *lasso_wsa_endpoint_reference_get_service(
		LassoWsAddrEndpointReference *epr);

LASSO_EXPORT lasso_error_t lasso_wsa_endpoint_reference_associate_service_to_type(
		const char *service_type_uri, GType g_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_HELPER_H__ */

