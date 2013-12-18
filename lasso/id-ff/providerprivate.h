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

#ifndef __LASSO_PROVIDER_PRIVATE_H__
#define __LASSO_PROVIDER_PRIVATE_H__

#include <./serverprivate.h>
#include "../xml/private.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/**
 * LassoPublicKeyType:
 * @LASSO_PUBLIC_KEY_SIGNING: Signing public key
 * @LASSO_PUBLIC_KEY_ENCRYPTION: Encryption public key
 *
 * Public key type.
 */
typedef enum {
	LASSO_PUBLIC_KEY_SIGNING,
	LASSO_PUBLIC_KEY_ENCRYPTION
} LassoPublicKeyType;

/* This structure should allow to map ID-FFv1.2 and SAMLv2 endpoints */
struct EndpointType_s {
	LassoProviderRole role;
	char *kind;
	char *binding;
	char *url;
	char *return_url;
	int index;
	int is_default;
};
typedef struct EndpointType_s EndpointType;


struct _LassoProviderPrivate
{
	gboolean dispose_has_run;

	LassoProviderRole roles;
	LassoProtocolConformance conformance;
	GHashTable *Descriptors;
	GList *attributes; /* of LassoSaml2Attribute */
	char *default_assertion_consumer;
	xmlNode *organization;

	char *affiliation_owner_id;
	char *affiliation_id;

	GList *signing_public_keys;
	GList *signing_key_descriptors;
	xmlNode *encryption_key_descriptor;
	char *encryption_public_key_str;
	GList *encryption_public_keys;
	LassoEncryptionMode encryption_mode;
	LassoEncryptionSymKeyType encryption_sym_key_type;
	char *valid_until;
	char *cache_duration;
	GList *endpoints; /* of EndpointType_s */
	LassoSignatureContext signature_context;
};

gboolean lasso_provider_load_metadata(LassoProvider *provider, const gchar *metadata);
gboolean lasso_provider_load_metadata_from_buffer(LassoProvider *provider, const gchar *metadata);
gboolean lasso_provider_load_public_key(LassoProvider *provider,
		LassoPublicKeyType public_key_type);
GList* lasso_provider_get_public_keys(const LassoProvider *provider);
xmlSecKey* lasso_provider_get_encryption_public_key(const LassoProvider *provider);
LassoEncryptionSymKeyType lasso_provider_get_encryption_sym_key_type(const LassoProvider* provider);
int lasso_provider_verify_saml_signature(LassoProvider *provider, xmlNode *signed_node, xmlDoc *doc);
int lasso_provider_verify_query_signature(LassoProvider *provider, const char *message);
void _lasso_provider_load_key_descriptor(LassoProvider *provider, xmlNode *key_descriptor);
void _lasso_provider_add_metadata_value_for_role(LassoProvider *provider,
		LassoProviderRole role, const char *name, const char *value);
LassoProvider* lasso_provider_new_from_xmlnode(LassoProviderRole role, xmlNode *node);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROVIDER_PRIVATE_H__ */
