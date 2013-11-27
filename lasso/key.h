/*
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2011 Entr'ouvert
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

#ifndef __LASSO_KEY_H__
#define __LASSO_KEY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml/xml.h"

#define LASSO_TYPE_KEY (lasso_key_get_type())
#define LASSO_KEY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_KEY, \
				LassoKey))
#define LASSO_KEY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_KEY, \
				LassoKeyClass))
#define LASSO_IS_KEY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_KEY))
#define LASSO_IS_KEY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_KEY))
#define LASSO_KEY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_KEY, \
				LassoKeyClass))

typedef struct _LassoKey LassoKey;
typedef struct _LassoKeyClass LassoKeyClass;
typedef struct _LassoKeyPrivate LassoKeyPrivate;

typedef enum _LassoKeyType {
	LASSO_KEY_TYPE_FOR_SIGNATURE,
} LassoKeyType;

struct _LassoKey {
	LassoNode parent;
	/*< private >*/
	LassoKeyPrivate *private_data;
};

struct _LassoKeyClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_key_get_type();

LASSO_EXPORT LassoKey* lasso_key_new_for_signature_from_memory(const void *buffer, size_t size,
		char *password, LassoSignatureMethod signature_method, char *certificate);

LASSO_EXPORT LassoKey* lasso_key_new_for_signature_from_base64_string(char *base64_string,
		char *password, LassoSignatureMethod signature_method, char *certificate);

LASSO_EXPORT LassoKey* lasso_key_new_for_signature_from_file(char *filename_or_buffer,
		char *password, LassoSignatureMethod signature_method, char *certificate);

LASSO_EXPORT lasso_error_t lasso_key_query_verify(LassoKey* key, const char *query);

LASSO_EXPORT char* lasso_key_query_sign(LassoKey *key, const char *query);

LASSO_EXPORT lasso_error_t lasso_key_saml2_xml_verify(LassoKey *key, char *id, xmlNode *document);

LASSO_EXPORT xmlNode *lasso_key_saml2_xml_sign(LassoKey *key, const char *id, xmlNode *document);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_KEY_H__ */
