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

#ifndef __LASSO_IDENTITY_H__
#define __LASSO_IDENTITY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"
#include "federation.h"

#define LASSO_TYPE_IDENTITY (lasso_identity_get_type())
#define LASSO_IDENTITY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_IDENTITY, LassoIdentity))
#define LASSO_IDENTITY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_IDENTITY, LassoIdentityClass))
#define LASSO_IS_IDENTITY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_IDENTITY))
#define LASSO_IS_IDENTITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_IDENTITY))
#define LASSO_IDENTITY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_IDENTITY, LassoIdentityClass))

typedef struct _LassoIdentity LassoIdentity;
typedef struct _LassoIdentityClass LassoIdentityClass;
typedef struct _LassoIdentityPrivate LassoIdentityPrivate;

struct _LassoIdentity {
	LassoNode parent;

	/*< public >*/
	GHashTable *federations; /* of LassoFederation */
	gboolean is_dirty;

	/*< private >*/
	LassoIdentityPrivate *private_data;
};

struct _LassoIdentityClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_identity_get_type(void);
LASSO_EXPORT LassoIdentity* lasso_identity_new(void);
LASSO_EXPORT LassoIdentity* lasso_identity_new_from_dump(const gchar *dump);

LASSO_EXPORT LassoFederation* lasso_identity_get_federation(
		LassoIdentity *identity, const char *providerID);

LASSO_EXPORT void lasso_identity_destroy(LassoIdentity *identity);

LASSO_EXPORT gchar* lasso_identity_dump(LassoIdentity *identity);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDENTITY_H__ */
