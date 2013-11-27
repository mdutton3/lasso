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

#ifndef __LASSO_SAML20_PROVIDER_PRIVATE_H__
#define __LASSO_SAML20_PROVIDER_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"
#include "../id-ff/provider.h"

gboolean lasso_saml20_provider_load_metadata(LassoProvider *provider, xmlNode *root_node);

LassoHttpMethod lasso_saml20_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type);

gboolean lasso_saml20_provider_accept_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type,
		LassoHttpMethod http_method, gboolean initiate_profile);

char* lasso_saml20_provider_build_artifact(LassoProvider *provider);

gchar* lasso_saml20_provider_get_assertion_consumer_service_url(LassoProvider *provider,
		int service_id);
gchar* lasso_saml20_provider_get_assertion_consumer_service_binding(LassoProvider *provider,
		int service_id);
gchar* lasso_saml20_provider_get_assertion_consumer_service_url_by_binding(LassoProvider *provider,
		const gchar *binding);
gboolean lasso_saml20_provider_check_assertion_consumer_service_url(LassoProvider *provider,
		const gchar *url, const gchar *binding);
const gchar* lasso_saml20_provider_get_assertion_consumer_service_binding_by_url(
		LassoProvider *provider, const char *url);
lasso_error_t lasso_saml20_provider_get_artifact_resolution_service_index(LassoProvider *provider,
		unsigned short *index);
const gchar* lasso_saml20_provider_get_endpoint_url(LassoProvider *provider, LassoProviderRole role,
		const char *kind, GSList *bindings, gboolean is_response, gboolean is_default,
		int idx);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML20_PROVIDER_PRIVATE_H__ */
