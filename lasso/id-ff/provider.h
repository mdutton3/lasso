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

#ifndef __LASSO_PROVIDER_H__
#define __LASSO_PROVIDER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"
#include "../xml/xml_enc.h"
#include "../key.h"

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
 * @LASSO_HTTP_METHOD_PAOS: PAOS/HTTP based (SAML 2.0)
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
	LASSO_HTTP_METHOD_ARTIFACT_POST,
	LASSO_HTTP_METHOD_PAOS,
	LASSO_HTTP_METHOD_LAST
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
	LASSO_MD_PROTOCOL_TYPE_ASSERTION_ID_REQUEST,
	LASSO_MD_PROTOCOL_TYPE_AUTHN_QUERY,
	LASSO_MD_PROTOCOL_TYPE_AUTHZ,
	LASSO_MD_PROTOCOL_TYPE_ATTRIBUTE,
	LASSO_MD_PROTOCOL_TYPE_LAST
} LassoMdProtocolType;


/**
 * LassoProviderRole:
 * @LASSO_PROVIDER_ROLE_NONE: unitialized value (internal use)
 * @LASSO_PROVIDER_ROLE_SP: service provider.
 * @LASSO_PROVIDER_ROLE_IDP: identity provider.
 * @LASSO_PROVIDER_ROLE_BOTH: service&identity provider.
 * @LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY: an authentification authority, i.e. an endpoint able to
 * return previously returned assertion,
 * @LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY: an authorization authority, i.e. an endpoint able to return
 * assertion providing authorization about a principal acessing a resource,
 * @LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY: an attribute authority, i.e. an endpoint able to return
 * attributes aboute a principal,
 * @LASSO_PROVIDER_ROLE_LAST: all values in the enumeration are guaranteed to be < to
 * @LASSO_PROVIDER_ROLE_LAST.
 *
 * #LassoProviderRole is an enumeration allowing to enumerate the roles handled by a provider, it
 * can be used in a bitmask as each value is a power of 2 (except #LASSO_PROVIDER_ROLE_ANY which is
 * the full bitmask and LASSO_PROVIDER_ROLE_NONE).
 **/
typedef enum {
	LASSO_PROVIDER_ROLE_ANY = -1,
	LASSO_PROVIDER_ROLE_NONE = 0,
	LASSO_PROVIDER_ROLE_SP = 1,
	LASSO_PROVIDER_ROLE_IDP = 2,
	LASSO_PROVIDER_ROLE_BOTH = 3,
	LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY = 4,
	LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY = 8,
	LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY = 16,
	LASSO_PROVIDER_ROLE_LAST = 17,
	LASSO_PROVIDER_ROLE_ALL = 31
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
	LASSO_ENCRYPTION_MODE_ASSERTION
} LassoEncryptionMode;


/**
 * LassoProvider:
 * @ProviderID: the identifier URI of this provider
 * @role: the role prescribed when this #LassoProvider was built
 * @metadata_filename: file path or content of the metadata description for this provider.
 * @public_key: file path or content of the public key file for this provider.
 * @ca_cert_chain: file path or content of the CA cert chain used to validate signature of this
 * provider (can be used instead of a public key to limit the need for metadata updates).
 *
 * <para>Any kind of provider, identity provider, service provider, attribute authority, authorization
 * authority will be represented by a #LassoProvider object. This object will holds public keys,
 * certificate chains and metadata informations. The ID-FF 1.2 and SAML 2.0 metadata files are
 * flattened inside a key-value map that you can access using the functions
 * lasso_provider_get_metadata_one_for_role(), lasso_provider_get_metadata_list_for_role(),
 * lasso_provider_get_metadata_keys_for_role().</para>
 */
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

LASSO_EXPORT gchar* lasso_provider_get_base64_succinct_id(const LassoProvider *provider);

LASSO_EXPORT xmlNode* lasso_provider_get_organization(const LassoProvider *provider);

LASSO_EXPORT LassoProtocolConformance lasso_provider_get_protocol_conformance(
		const LassoProvider *provider);

LASSO_EXPORT void lasso_provider_set_encryption_mode(LassoProvider *provider,
		LassoEncryptionMode encryption_mode);

LASSO_EXPORT LassoEncryptionMode lasso_provider_get_encryption_mode(LassoProvider *provider);

LASSO_EXPORT void lasso_provider_set_encryption_sym_key_type(LassoProvider *provider,
		LassoEncryptionSymKeyType encryption_sym_key_type);

LASSO_EXPORT gchar* lasso_provider_get_default_name_id_format(LassoProvider *provider);

LASSO_EXPORT const char* lasso_provider_get_sp_name_qualifier(LassoProvider *provider);

LASSO_EXPORT lasso_error_t lasso_provider_verify_single_node_signature (LassoProvider *provider,
		LassoNode *node, const char *id_attr_name);

LASSO_EXPORT GList* lasso_provider_get_idp_supported_attributes(LassoProvider *provider);

LASSO_EXPORT char* lasso_provider_get_valid_until(LassoProvider *provider);

LASSO_EXPORT char* lasso_provider_get_cache_duration(LassoProvider *provider);

LASSO_EXPORT char* lasso_provider_get_metadata_one_for_role(LassoProvider *provider,
		LassoProviderRole role, const char *name);

LASSO_EXPORT GList* lasso_provider_get_metadata_list_for_role(const LassoProvider *provider,
		LassoProviderRole role, const char *name);

LASSO_EXPORT GList *lasso_provider_get_metadata_keys_for_role(LassoProvider *provider,
		LassoProviderRole role);

LASSO_EXPORT LassoProviderRole lasso_provider_get_roles(LassoProvider *provider);

LASSO_EXPORT gboolean lasso_provider_match_conformance(LassoProvider *provider, LassoProvider *another_provider);

LASSO_EXPORT lasso_error_t lasso_provider_set_server_signing_key(LassoProvider *provider,
		LassoKey *key);

LASSO_EXPORT lasso_error_t lasso_provider_add_key(LassoProvider *provider, LassoKey *key, gboolean after);

LASSO_EXPORT int lasso_provider_verify_signature(LassoProvider *provider,
		const char *message, const char *id_attr_name, LassoMessageFormat format);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROVIDER_H__ */
