/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_PROVIDER_H__
#define __LASSO_PROVIDER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_PROVIDER (lasso_provider_get_type())
#define LASSO_PROVIDER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROVIDER, LassoProvider))
#define LASSO_PROVIDER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PROVIDER, LassoProviderClass))
#define LASSO_IS_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROVIDER))
#define LASSO_IS_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROVIDER))
#define LASSO_PROVIDER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PROVIDER, LassoProviderClass)) 

typedef struct _LassoProvider LassoProvider;
typedef struct _LassoProviderClass LassoProviderClass;
typedef struct _LassoProviderPrivate LassoProviderPrivate;

typedef enum {
	LASSO_HTTP_METHOD_NONE = -1,
	LASSO_HTTP_METHOD_ANY,           /* any method will do */
	LASSO_HTTP_METHOD_IDP_INITIATED, /* no method, IdP initiated profile */
	LASSO_HTTP_METHOD_GET,           /* HTTP GET */
	LASSO_HTTP_METHOD_POST,          /* Browser POST */
	LASSO_HTTP_METHOD_REDIRECT,      /* HTTP-Redirect based */
	LASSO_HTTP_METHOD_SOAP           /* SOAP/HTTP based */
} lassoHttpMethod;

typedef enum {
	LASSO_MD_PROTOCOL_TYPE_FEDERATION_TERMINATION = 0, /* Federation Termination Notification */
	LASSO_MD_PROTOCOL_TYPE_NAME_IDENTIFIER_MAPPING,    /* Name Identifier Mapping */
	LASSO_MD_PROTOCOL_TYPE_REGISTER_NAME_IDENTIFIER,   /* Name Registration */
	LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT,              /* Single Logout */
	LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON              /* Single Sign-On and Federation */
} lassoMdProtocolType;

typedef enum {
	LASSO_PROVIDER_ROLE_NONE = 0,
	LASSO_PROVIDER_ROLE_SP,       /* Service Provider */
	LASSO_PROVIDER_ROLE_IDP       /* Identity Provider */
} LassoProviderRole;

struct _LassoProvider {
	LassoNode parent;

	/*< public >*/
	gchar *ProviderID;
	LassoProviderRole role;

	gchar *public_key;
	gchar *ca_cert_chain;

	/*< private >*/
	LassoProviderPrivate *private_data;
};

struct _LassoProviderClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_provider_get_type(void);
LASSO_EXPORT LassoProvider* lasso_provider_new(LassoProviderRole role, const char *metadata,
		const char *public_key, const char *ca_cert_chain);
LASSO_EXPORT gchar* lasso_provider_get_metadata_one(LassoProvider *provider, const char *name);
LASSO_EXPORT GList* lasso_provider_get_metadata_list(LassoProvider *provider, const char *name);

LASSO_EXPORT gboolean lasso_provider_load_metadata(LassoProvider *provider, const gchar *metadata);

LASSO_EXPORT LassoProvider* lasso_provider_new_from_dump(const gchar *dump);

LASSO_EXPORT int lasso_provider_verify_signature(LassoProvider *provider,
		const char *message, const char *id_attr_name, LassoMessageFormat format);

LASSO_EXPORT lassoHttpMethod lasso_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, lassoMdProtocolType protocol_type);

LASSO_EXPORT gboolean lasso_provider_accept_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, lassoMdProtocolType protocol_type,
		lassoHttpMethod http_method, gboolean initiate_profile);

LASSO_EXPORT gboolean lasso_provider_has_protocol_profile(LassoProvider *provider,
		lassoMdProtocolType protocol_type, const char *protocol_profile);

LASSO_EXPORT gchar* lasso_provider_get_base64_succint_id(LassoProvider *provider);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROVIDER_H__ */
