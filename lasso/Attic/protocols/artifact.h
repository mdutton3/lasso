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

#ifndef __LASSO_ARTIFACT_H__
#define __LASSO_ARTIFACT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_ARTIFACT (lasso_artifact_get_type())
#define LASSO_ARTIFACT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_ARTIFACT, LassoArtifact))
#define LASSO_ARTIFACT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_ARTIFACT, LassoArtifactClass))
#define LASSO_IS_ARTIFACT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_ARTIFACT))
#define LASSO_IS_ARTIFACT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_ARTIFACT))
#define LASSO_ARTIFACT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_ARTIFACT, LassoArtifactClass)) 

typedef struct _LassoArtifact LassoArtifact;
typedef struct _LassoArtifactClass LassoArtifactClass;

struct _LassoArtifact {
  LassoNode parent;
  /*< public >*/
  /*< private >*/
};

struct _LassoArtifactClass {
  LassoNodeClass parent;
};

LASSO_EXPORT GType      lasso_artifact_get_type                          (void);

LASSO_EXPORT LassoNode* lasso_artifact_new                               (gchar *samlArt,
									  gchar *byteCode,
									  gchar *identityProviderSuccinctID,
									  gchar *assertionHandle,
									  gchar *relayState);

LASSO_EXPORT LassoNode* lasso_artifact_new_from_query                    (const xmlChar *query);

LASSO_EXPORT LassoNode* lasso_artifact_new_from_lares                    (const xmlChar *lares,
									  const xmlChar *relayState);

LASSO_EXPORT xmlChar*   lasso_artifact_get_assertionHandle               (LassoArtifact  *artifact,
									  GError        **err);

LASSO_EXPORT gint       lasso_artifact_get_byteCode                      (LassoArtifact  *artifact,
									  GError        **err);

LASSO_EXPORT xmlChar*   lasso_artifact_get_b64IdentityProviderSuccinctID (LassoArtifact  *artifact,
									  GError        **err);

LASSO_EXPORT xmlChar*   lasso_artifact_get_relayState                    (LassoArtifact  *artifact,
									  GError        **err);

LASSO_EXPORT xmlChar*   lasso_artifact_get_samlArt                       (LassoArtifact  *artifact,
									  GError        **err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ARTIFACT_H__ */
