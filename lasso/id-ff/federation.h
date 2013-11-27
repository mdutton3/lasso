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

#ifndef __LASSO_FEDERATION_H__
#define __LASSO_FEDERATION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"
#include "../xml/saml_name_identifier.h"

#define LASSO_TYPE_FEDERATION (lasso_federation_get_type())
#define LASSO_FEDERATION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_FEDERATION, LassoFederation))
#define LASSO_FEDERATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_FEDERATION, LassoFederationClass))
#define LASSO_IS_FEDERATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_FEDERATION))
#define LASSO_IS_FEDERATION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_FEDERATION))
#define LASSO_FEDERATION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_FEDERATION, LassoFederationClass))

typedef struct _LassoFederation LassoFederation;
typedef struct _LassoFederationClass LassoFederationClass;
typedef struct _LassoFederationPrivate LassoFederationPrivate;

struct _LassoFederation {
	LassoNode parent;

	/*< public >*/
	gchar *remote_providerID;
	LassoNode *local_nameIdentifier;
	LassoNode *remote_nameIdentifier;

	/*< private >*/
	LassoFederationPrivate *private_data;
};

struct _LassoFederationClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_federation_get_type(void);

LASSO_EXPORT LassoFederation* lasso_federation_new(const gchar *remote_providerID);

LASSO_EXPORT void lasso_federation_build_local_name_identifier(LassoFederation *federation,
		const gchar *nameQualifier, const gchar *format, const gchar *content);

LASSO_EXPORT void lasso_federation_destroy(LassoFederation *federation);

LASSO_EXPORT gboolean lasso_federation_verify_name_identifier(
		LassoFederation *federation, LassoNode *name_identifier);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_FEDERATION_H__ */
