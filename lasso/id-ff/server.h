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

#ifndef __LASSO_SERVER_H__
#define __LASSO_SERVER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "provider.h"

#define LASSO_TYPE_SERVER (lasso_server_get_type())
#define LASSO_SERVER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SERVER, LassoServer))
#define LASSO_SERVER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SERVER, LassoServerClass))
#define LASSO_IS_SERVER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SERVER))
#define LASSO_IS_SERVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SERVER))
#define LASSO_SERVER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SERVER, LassoServerClass))

typedef struct _LassoServer LassoServer;
typedef struct _LassoServerClass LassoServerClass;
typedef struct _LassoServerPrivate LassoServerPrivate;

struct _LassoServer {
	LassoProvider parent;

	/*< public >*/
	GHashTable *providers; /* of LassoProvider */
	/* Can actually contain LassoDataService or LassoIdWsf2DataService or any subclass */
	/*< private >*/
	GHashTable *services; /* of LassoDataService */
	/*< public >*/

	gchar *private_key;
	gchar *private_key_password;
	gchar *certificate;
	LassoSignatureMethod signature_method;

	/*< private >*/
	LassoServerPrivate *private_data;
};

struct _LassoServerClass {
	LassoProviderClass parent;
};

/**
 * LassoServerLoadMetadataFlag:
 * @LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT: the default policy is to check signature on entity and
 * entities descriptor, and to let signature be inherited by child nodes.
 * @LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITIES_DESCRIPTOR_SIGNATURE: check signature on
 * EntitiesDesctiptor nodes,
 * @LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITY_DESCRIPTOR_SIGNATURE: check signature on
 * EntityDescriptor nodes,
 * @LASSO_SERVER_LOAD_METADATA_FLAG_INHERIT_SIGNATURE: when an EntitiesDescriptor is signed, all its
 * children inherit the trust from this signature and their signature is not checked.
 */
typedef enum {
	LASSO_SERVER_LOAD_METADATA_FLAG_DEFAULT = 0,
	LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITIES_DESCRIPTOR_SIGNATURE = 1,
	LASSO_SERVER_LOAD_METADATA_FLAG_CHECK_ENTITY_DESCRIPTOR_SIGNATURE = 2,
	LASSO_SERVER_LOAD_METADATA_FLAG_INHERIT_SIGNATURE = 4
} LassoServerLoadMetadataFlag;

LASSO_EXPORT GType lasso_server_get_type(void);

LASSO_EXPORT LassoServer* lasso_server_new(const gchar *metadata,
		const gchar *private_key,
		const gchar *private_key_password,
		const gchar *certificate);

LASSO_EXPORT LassoServer* lasso_server_new_from_buffers(const gchar *metadata,
		const gchar *private_key_content,
		const gchar *private_key_password,
		const gchar *certificate_content);

LASSO_EXPORT LassoServer* lasso_server_new_from_dump(const gchar *dump);

LASSO_EXPORT lasso_error_t lasso_server_add_provider (LassoServer *server,
		LassoProviderRole role, const gchar *metadata,
		const gchar *public_key, const gchar *ca_cert_chain);
LASSO_EXPORT lasso_error_t lasso_server_add_provider_from_buffer (LassoServer *server,
		LassoProviderRole role, const gchar *metadata,
		const gchar *public_key, const gchar *ca_cert_chain);

LASSO_EXPORT void lasso_server_destroy(LassoServer *server);

LASSO_EXPORT gchar* lasso_server_dump(LassoServer *server);

LASSO_EXPORT LassoProvider* lasso_server_get_provider(const LassoServer *server,
		const gchar *providerID);

LASSO_EXPORT lasso_error_t lasso_server_set_encryption_private_key(LassoServer *server,
		const gchar *filename_or_buffer);

LASSO_EXPORT lasso_error_t lasso_server_load_affiliation(LassoServer *server, const gchar* filename);

LASSO_EXPORT lasso_error_t lasso_server_set_encryption_private_key_with_password(LassoServer *server,
		const gchar *filename_or_buffer, const gchar *password);

LASSO_EXPORT lasso_error_t lasso_server_load_metadata(LassoServer *server, LassoProviderRole role,
		const gchar *federation_file, const gchar *trusted_roots, GList
		*blacklisted_entity_ids, GList **loaded_entity_ids,
		LassoServerLoadMetadataFlag flags);

LASSO_EXPORT lasso_error_t lasso_server_add_provider2(LassoServer *server, LassoProvider *provider);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SERVER_H__ */
