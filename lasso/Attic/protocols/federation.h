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

#ifndef __LASSO_FEDERATION_H__
#define __LASSO_FEDERATION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/saml_name_identifier.h>

#define LASSO_TYPE_FEDERATION (lasso_federation_get_type())
#define LASSO_FEDERATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_FEDERATION, LassoFederation))
#define LASSO_FEDERATION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_FEDERATION, LassoFederationClass))
#define LASSO_IS_FEDERATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_FEDERATION))
#define LASSO_IS_FEDERATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_FEDERATION))
#define LASSO_FEDERATION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_FEDERATION, LassoFederationClass)) 

#define LASSO_FEDERATION_NODE "Federation"
#define LASSO_FEDERATION_REMOTE_PROVIDERID_NODE "RemoteProviderID"
#define LASSO_FEDERATION_LOCAL_NAME_IDENTIFIER_NODE "LocalNameIdentifier"
#define LASSO_FEDERATION_REMOTE_NAME_IDENTIFIER_NODE "RemoteNameIdentifier"

typedef struct _LassoFederation LassoFederation;
typedef struct _LassoFederationClass LassoFederationClass;
typedef struct _LassoFederationPrivate LassoFederationPrivate;

struct _LassoFederation {
  GObject parent;
  
  gchar *remote_providerID;

  LassoNode *local_nameIdentifier;
  LassoNode *remote_nameIdentifier;

  /*< private >*/
  LassoFederationPrivate *private;
};

struct _LassoFederationClass {
  GObjectClass parent;
};

LASSO_EXPORT GType            lasso_federation_get_type                     (void);

LASSO_EXPORT LassoFederation* lasso_federation_new                          (gchar *remote_providerID);

LASSO_EXPORT LassoFederation* lasso_federation_new_from_dump                (gchar *dump);

LASSO_EXPORT void             lasso_federation_build_local_nameIdentifier   (LassoFederation *federation,
									     const gchar     *nameQualifier,
									     const gchar     *format,
									     const gchar     *content);

LASSO_EXPORT void             lasso_federation_build_remote_nameIdentifier  (LassoFederation *federation,
									     const gchar     *nameQualifier,
									     const gchar     *format,
									     const gchar     *content);

LASSO_EXPORT LassoFederation* lasso_federation_copy                         (LassoFederation *federation);

LASSO_EXPORT void             lasso_federation_destroy                      (LassoFederation *federation);

LASSO_EXPORT gchar*           lasso_federation_dump                         (LassoFederation *federation);

LASSO_EXPORT LassoNode*       lasso_federation_get_remote_nameIdentifier    (LassoFederation *federation);

LASSO_EXPORT LassoNode*       lasso_federation_get_local_nameIdentifier     (LassoFederation *federation);

LASSO_EXPORT void             lasso_federation_remove_local_nameIdentifier  (LassoFederation *federation);

LASSO_EXPORT void             lasso_federation_remove_remote_nameIdentifier (LassoFederation *federation);

LASSO_EXPORT void             lasso_federation_set_local_nameIdentifier     (LassoFederation *federation,
									     LassoNode       *nameIdentifier);

LASSO_EXPORT void             lasso_federation_set_remote_nameIdentifier    (LassoFederation *federation,
									     LassoNode       *nameIdentifier);

LASSO_EXPORT gboolean         lasso_federation_verify_nameIdentifier        (LassoFederation *federation,
									     LassoNode       *nameIdentifier);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_FEDERATION_H__ */
