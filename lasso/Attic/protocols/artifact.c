/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/protocols/artifact.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

xmlChar*
lasso_artifact_get_assertionHandle(LassoArtifact *artifact)
{
  return (lasso_node_get_child_content(LASSO_NODE(artifact), "AssertionHandle", NULL));
}

gint
lasso_artifact_get_byteCode(LassoArtifact *artifact)
{
  xmlChar *byteCode;

  byteCode = lasso_node_get_child_content(LASSO_NODE(artifact), "ByteCode", NULL);
  return ((gint)g_strtod(byteCode, NULL));
}

xmlChar*
lasso_artifact_get_identityProviderSuccinctID(LassoArtifact *artifact)
{
  return (lasso_node_get_child_content(LASSO_NODE(artifact), "IdentityProviderSuccinctID", NULL));
}

xmlChar*
lasso_artifact_get_relayState(LassoArtifact *artifact)
{
  return (lasso_node_get_child_content(LASSO_NODE(artifact), "RelayState", NULL));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_artifact_instance_init(LassoArtifact *artifact)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(artifact));

  class->set_name(LASSO_NODE(artifact), "Artifact");
}

static void
lasso_artifact_class_init(LassoArtifactClass *class)
{
}

GType lasso_artifact_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoArtifactClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_artifact_class_init,
      NULL,
      NULL,
      sizeof(LassoArtifact),
      0,
      (GInstanceInitFunc) lasso_artifact_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoArtifact",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_artifact_new(const xmlChar *query)
{
  LassoNode *artifact;
  LassoNodeClass *class;
  GData *gd;
  gchar *b64_samlArt, *samlArt, *relayState, *byteCode, *identityProviderSuccinctID, *assertionHandle;
  gint i, j, byte_code=0;

  artifact = LASSO_NODE(g_object_new(LASSO_TYPE_ARTIFACT, NULL));

  gd = lasso_query_to_dict(query);
  b64_samlArt = g_strdup(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SAMLArt"), 0));
  relayState  = g_strdup(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0));
  g_datalist_clear(&gd);

  /* extract ByteCode, IdentityProviderSuccinctID and AssertionHandle */
  samlArt = (gchar *) g_new0(gchar, 42+1);
  byteCode = (gchar *) g_new0(gchar, 5+1);
  identityProviderSuccinctID = (gchar *) g_new0(gchar, 20+1);
  assertionHandle = (gchar *) g_new0(gchar, 20+1);

  i = xmlSecBase64Decode(b64_samlArt, samlArt, 42+1);
  xmlFree(b64_samlArt);
  for(j=0; j<42; j++) {
    if (j<2) {
      byte_code += (gint)samlArt[j];
    }
    else if (j>=2 && j<22) {
      identityProviderSuccinctID[j-2] = samlArt[j];
    }
    else if (j>=22) {
      assertionHandle[j-22] = samlArt[j];
    }
  }
  sprintf(byteCode, "%d", byte_code);
  xmlFree(samlArt);

  class = LASSO_NODE_GET_CLASS(artifact);
  class->new_child(artifact, "RelayState", relayState, FALSE);
  class->new_child(artifact, "ByteCode", byteCode, FALSE);
  class->new_child(artifact, "IdentityProviderSuccinctID", identityProviderSuccinctID, FALSE);
  class->new_child(artifact, "AssertionHandle", assertionHandle, FALSE);

  return (artifact);
}
