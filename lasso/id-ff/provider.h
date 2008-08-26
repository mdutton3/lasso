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

#ifndef __LASSO_PROVIDER_H__
#define __LASSO_PROVIDER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/xml_enc.h>

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


/**
 * LassoHttpMethod:
 * @LASSO_HTTP_METHOD_NONE: invalid value (internal use)
 * @LASSO_HTTP_METHOD_ANY: any method will do
 * @LASSO_HTTP_METHOD_IDP_INITIATED: not a method, for IdP initiated profile
 * @LASSO_HTTP_METHOD_GET: HTTP GET
 * @LASSO_HTTP_METHOD_POST: Browser POST
 * @LASSO_HTTP_METHOD_REDIRECT: HTTP-Redirect based
 * @LASSO_HTTP_METHOD_SOAP: SOAP/HTTP based
 * @LASSO_HTTP_METHOD_ARTIFACT_GET: Artifact by HTTP GET (SAML 2.0)
 * @LASSO_HTTP_METHOD_ARTIFACT_POST: Artifact by HTTP POST (SAML 2.0)
 *
 * Method.
 **/
typedef enum {
	LASSO_HTTP_METHOD_NONE = -1,
	LASSO_HTTP_METHOD_ANY,
	LASSO_HTTP_METHOD_IDP_INITIATED,
	LASSO_HTTP_METHOD_GET,
	LASSO_HTTP_METHOD_POST,
	LASSO_HTTP_METHOD_REDIRECT,
	LASSO_HTTP_METHOD_SOAP,
	LASSO_HTTP_METHOD_ARTIFACT_GET,
	LASSO_HTTP_METHOD_ARTIFACT_POST
} LassoHttpMethod;


/**
 * LassoMdProtocolType:
 * @LASSO_MD_PROTOCOL_TYPE_FEDERATION_TERMINATION: Federation Termination Notification
 * @LASSO_MD_PROTOCOL_TYPE_NAME_IDENTIFIER_MAPPING: Name Identifier Mapping
 * @LASSO_MD_PROTOCOL_TYPE_REGISTER_NAME_IDENTIFIER: Name Registration
 * @LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT: Single Logout
 * @LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON: Single Sign-On and Federation
 * @LASSO_MD_PROTOCOL_TYPE_ARTIFACT_RESOLUTION: Artifact Resolution (SAML 2.0)
 * @LASSO_MD_PROTOCOL_TYPE_MANAGE_NAME_ID: Manage Name Identifier (SAML 2.0)
 * @LASSO_MD_PROTOCOL_TYPE_ASSERTION_ID_REQUEST: Assertion ID Request (SAML 2.0)
 *
 * Liberty Metadata Type.
 **/
typedef enum {
	LASSO_MD_PROTOCOL_TYPE_FEDERATION_TERMINATION,
	LASSO_MD_PROTOCOL_TYPE_NAME_IDENTIFIER_MAPPING,
	LASSO_MD_PROTOCOL_TYPE_REGISTER_NAME_IDENTIFIER,
	LASSO_MD_PROTOCOL_TYPE_SINGLE_LOGOUT,
	LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON,
	LASSO_MD_PROTOCOL_TYPE_ARTIFACT_RESOLUTION,
	LASSO_MD_PROTOCOL_TYPE_MANAGE_NAME_ID,
	LASSO_MD_PROTOCOL_TYPE_ASSERTION_ID_REQUEST
} LassoMdProtocolType;


/**
 * LassoProviderRole:
 * @LASSO_PROVIDER_ROLE_NONE: unitialized value (internal use)
 * @LASSO_PROVIDER_ROLE_SP: service provider
 * @LASSO_PROVIDER_ROLE_IDP: identity provider
 *
 * Provider Role.
 **/
typedef enum {
	LASSO_PROVIDER_ROLE_NONE = 0,
	LASSO_PROVIDER_ROLE_SP,
	LASSO_PROVIDER_ROLE_IDP
} LassoProviderRole;


/**
 * LassoProtocolConformance:
 * @LASSO_PROTOCOL_LIBERTY_1_0: Liberty ID-FF 1.0
 * @LASSO_PROTOCOL_LIBERTY_1_1: Liberty ID-FF 1.1
 * @LASSO_PROTOCOL_LIBERTY_1_2: Liberty ID-FF 1.2 / ID-WSF 1.0
 * @LASSO_PROTOCOL_SAML_2_0: SAML 2.0
 *
 * Provider protocol conformance.
 **/
typedef enum {
	LASSO_PROTOCOL_NONE = -1,
	LASSO_PROTOCOL_LIBERTY_1_0,
	LASSO_PROTOCOL_LIBERTY_1_1,
	LASSO_PROTOCOL_LIBERTY_1_2,
	LASSO_PROTOCOL_SAML_2_0
} LassoProtocolConformance;


/**
 * LassoEncryptionMode:
 * @LASSO_ENCRYPTION_MODE_NONE: Encrypt nothing
 * @LASSO_ENCRYPTION_MODE_NAMEID: Encrypt NameIDs
 * @LASSO_ENCRYPTION_MODE_ASSERTION : Encrypt Assertions
 *
 * Encryption mode.
 **/
typedef enum {
	LASSO_ENCRYPTION_MODE_NONE,
	LASSO_ENCRYPTION_MODE_NAMEID,
	LASSO_ENCRYPTION_MODE_ASSERTION,
} LassoEncryptionMode;


struct _LassoProvider {
	LassoNode parent;

	/*< public >*/
	gchar *ProviderID;
	LassoProviderRole role;

	char *metadata_filename;
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
LASSO_EXPORT LassoProvider* lasso_provider_new_from_buffer(LassoProviderRole role, 
		const char *metadata, const char *public_key, const char *ca_cert_chain);
LASSO_EXPORT gchar* lasso_provider_get_assertion_consumer_service_url(LassoProvider *provider,
		const char *service_id);
LASSO_EXPORT gchar* lasso_provider_get_metadata_one(LassoProvider *provider, const char *name);
LASSO_EXPORT GList* lasso_provider_get_metadata_list(LassoProvider *provider, const char *name);

LASSO_EXPORT LassoProvider* lasso_provider_new_from_dump(const gchar *dump);

LASSO_EXPORT LassoHttpMethod lasso_provider_get_first_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type);

LASSO_EXPORT gboolean lasso_provider_accept_http_method(LassoProvider *provider,
		LassoProvider *remote_provider, LassoMdProtocolType protocol_type,
		LassoHttpMethod http_method, gboolean initiate_profile);

LASSO_EXPORT gboolean lasso_provider_has_protocol_profile(LassoProvider *provider,
		LassoMdProtocolType protocol_type, const char *protocol_profile);

LASSO_EXPORT gchar* lasso_provider_get_base64_succinct_id(LassoProvider *provider);

LASSO_EXPORT xmlNode* lasso_provider_get_organization(LassoProvider *provider);

LASSO_EXPORT LassoProtocolConformance lasso_provider_get_protocol_conformance(
		LassoProvider *provider);

LASSO_EXPORT void lasso_provider_set_encryption_mode(LassoProvider *provider,
		LassoEncryptionMode encryption_mode);

LASSO_EXPORT void lasso_provider_set_encryption_sym_key_type(LassoProvider *provider,
		LassoEncryptionSymKeyType encryption_sym_key_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROVIDER_H__ */
