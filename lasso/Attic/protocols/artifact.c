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

#include <lasso/xml/errors.h>
#include <lasso/protocols/artifact.h>
#include <xmlsec/base64.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

static gint
lasso_artifact_split_samlArt(gchar *b64_samlArt,
			     gchar *byteCode,
			     gchar *identityProviderSuccinctID,
			     gchar *assertionHandle)
{
  xmlSecByte samlArt[42+1];
  gint i, j, byte_code = 0;

  /* decode samlArt */
  i = xmlSecBase64Decode((const xmlChar *)b64_samlArt, samlArt, 42+1);
  if (i < 0 || i > 42) {
    return -1;
  }
  /* extract ByteCode, IdentityProviderSuccinctID and AssertionHandle */
  for(j=0; j<42; j++) {
    if (j < 2) {
      byte_code += (guint)samlArt[j];
    }
    else if (j >= 2 && j < 22) {
      identityProviderSuccinctID[j-2] = samlArt[j];
    }
    else if (j >= 22) {
      assertionHandle[j-22] = samlArt[j];
    }
  }
  sprintf(byteCode, "%d", byte_code);

  return 0;
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

xmlChar*
lasso_artifact_get_assertionHandle(LassoArtifact  *artifact,
				   GError        **err)
{
  xmlChar *assertionHandle;
  GError *tmp_err = NULL;

  if (err != NULL && *err != NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_CHECK_FAILED,
		lasso_strerror(LASSO_PARAM_ERROR_CHECK_FAILED));
    g_return_val_if_fail (err == NULL || *err == NULL, NULL);
  }
  if (LASSO_IS_ARTIFACT(artifact) == FALSE) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ,
		lasso_strerror(LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ));
    g_return_val_if_fail(LASSO_IS_ARTIFACT(artifact), NULL);
  }

  assertionHandle = lasso_node_get_child_content(LASSO_NODE(artifact),
						 "AssertionHandle",
						 NULL, &tmp_err);
  if (assertionHandle == NULL) {
    g_propagate_error (err, tmp_err);
  }

  return assertionHandle;
}

/**
 * lasso_artifact_get_byteCode:
 * @artifact: an LassoArtifact
 * @err: return location for an allocated GError, or NULL to ignore errors
 * 
 * Gets the ByteCode of the artifact
 * 
 * Return value: the ByteCode or a negative integer if an error occurs.
 **/
gint
lasso_artifact_get_byteCode(LassoArtifact  *artifact,
			    GError        **err)
{
  xmlChar *byteCode;
  gint ret;
  GError *tmp_err = NULL;

  if (err != NULL && *err != NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_CHECK_FAILED,
		lasso_strerror(LASSO_PARAM_ERROR_CHECK_FAILED));
    g_return_val_if_fail (err == NULL || *err == NULL,
			  LASSO_PARAM_ERROR_CHECK_FAILED);
  }
  if (LASSO_IS_ARTIFACT(artifact) == FALSE) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ,
		lasso_strerror(LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ));
    g_return_val_if_fail(LASSO_IS_ARTIFACT(artifact),
			 LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
  }

  byteCode = lasso_node_get_child_content(LASSO_NODE(artifact),
					  "ByteCode", NULL, &tmp_err);
  if (byteCode == NULL) {
    g_propagate_error (err, tmp_err);
    return -1;
  }

  ret = (gint)g_strtod(byteCode, NULL);
  xmlFree(byteCode);

  return ret;
}

xmlChar*
lasso_artifact_get_b64IdentityProviderSuccinctID(LassoArtifact  *artifact,
						 GError        **err)
{
  xmlChar *b64_identityProviderSuccinctID;
  GError *tmp_err = NULL;

  if (err != NULL && *err != NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_CHECK_FAILED,
		lasso_strerror(LASSO_PARAM_ERROR_CHECK_FAILED));
    g_return_val_if_fail (err == NULL || *err == NULL, NULL);
  }
  if (LASSO_IS_ARTIFACT(artifact) == FALSE) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ,
		lasso_strerror(LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ));
    g_return_val_if_fail(LASSO_IS_ARTIFACT(artifact), NULL);
  }

  b64_identityProviderSuccinctID = lasso_node_get_child_content(LASSO_NODE(artifact),
								"B64IdentityProviderSuccinctID",
								NULL, &tmp_err);
  if (b64_identityProviderSuccinctID == NULL) {
    g_propagate_error (err, tmp_err);
  }

  return b64_identityProviderSuccinctID;
}

xmlChar*
lasso_artifact_get_relayState(LassoArtifact  *artifact,
			      GError        **err)
{
  xmlChar *relayState;
  GError *tmp_err = NULL;

  if (err != NULL && *err != NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_CHECK_FAILED,
		lasso_strerror(LASSO_PARAM_ERROR_CHECK_FAILED));
    g_return_val_if_fail (err == NULL || *err == NULL, NULL);
  }
  if (LASSO_IS_ARTIFACT(artifact) == FALSE) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ,
		lasso_strerror(LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ));
    g_return_val_if_fail(LASSO_IS_ARTIFACT(artifact), NULL);
  }

  relayState = lasso_node_get_child_content(LASSO_NODE(artifact),
					    "RelayState", NULL, &tmp_err);
  if (relayState == NULL) {
    g_propagate_error (err, tmp_err);
  }

  return relayState;
}

xmlChar*
lasso_artifact_get_samlArt(LassoArtifact  *artifact,
			   GError        **err)
{
  xmlChar *samlArt;
  GError *tmp_err = NULL;

  if (err != NULL && *err != NULL) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_CHECK_FAILED,
		lasso_strerror(LASSO_PARAM_ERROR_CHECK_FAILED));
    g_return_val_if_fail (err == NULL || *err == NULL, NULL);
  }
  if (LASSO_IS_ARTIFACT(artifact) == FALSE) {
    g_set_error(err, g_quark_from_string("Lasso"),
		LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ,
		lasso_strerror(LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ));
    g_return_val_if_fail(LASSO_IS_ARTIFACT(artifact), NULL);
  }

  samlArt = lasso_node_get_child_content(LASSO_NODE(artifact),
					 "SAMLart", NULL, &tmp_err);
  if (samlArt == NULL) {
    g_propagate_error (err, tmp_err);
  }

  return samlArt;
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
lasso_artifact_new(gchar *samlArt,
		   gchar *byteCode,
		   gchar *identityProviderSuccinctID,
		   gchar *assertionHandle,
		   gchar *relayState)
{
  LassoNode *artifact;
  LassoNodeClass *class;
  xmlChar *b64_identityProviderSuccinctID;

  g_return_val_if_fail(byteCode != NULL, NULL);
  g_return_val_if_fail(identityProviderSuccinctID != NULL, NULL);
  g_return_val_if_fail(assertionHandle != NULL, NULL);

  artifact = LASSO_NODE(g_object_new(LASSO_TYPE_ARTIFACT, NULL));

  class = LASSO_NODE_GET_CLASS(artifact);
  class->new_child(artifact, "SAMLart", samlArt, FALSE);
  class->new_child(artifact, "ByteCode", byteCode, FALSE);
  b64_identityProviderSuccinctID = xmlSecBase64Encode((const xmlSecByte *)identityProviderSuccinctID,
						      20, 0);
  class->new_child(artifact, "B64IdentityProviderSuccinctID",
		   b64_identityProviderSuccinctID, FALSE);
  xmlFree(b64_identityProviderSuccinctID);
  class->new_child(artifact, "AssertionHandle", assertionHandle, FALSE);
  if (relayState != NULL) {
    class->new_child(artifact, "RelayState", relayState, FALSE);
  }

  return artifact;
}

LassoNode*
lasso_artifact_new_from_query(const xmlChar *query)
{
  LassoNode *artifact = NULL;
  GData *gd;
  gchar *b64_samlArt, *relayState;
  gchar *byteCode, *identityProviderSuccinctID, *assertionHandle;
  gint ret;

  g_return_val_if_fail(query != NULL, NULL);


  gd = lasso_query_to_dict(query);
  b64_samlArt = g_strdup(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SAMLart"), 0));
  relayState  = g_strdup(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0));
  g_datalist_clear(&gd);

  byteCode = (gchar *) g_new0(gchar, 5+1);
  identityProviderSuccinctID = (gchar *) g_new0(gchar, 21);
  assertionHandle = (gchar *) g_new0(gchar, 20+1);
  ret = lasso_artifact_split_samlArt((gchar*)b64_samlArt, byteCode,
				     identityProviderSuccinctID,
				     assertionHandle);

  /* printf("b64_samlArt = %s\n", b64_samlArt); */
  /* printf("relayState = %s\n", relayState); */
  /* printf("byteCode = %s\n", byteCode); */
  /* printf("identityProviderSuccinctID = %s\n", identityProviderSuccinctID); */
  /* printf("assertionHandle = %s\n", assertionHandle); */

  if (ret >= 0) {
    artifact = lasso_artifact_new(b64_samlArt,
				  byteCode, identityProviderSuccinctID,
				  assertionHandle,
				  relayState);
  }
  g_free(byteCode);
  g_free(identityProviderSuccinctID);
  g_free(assertionHandle);
  g_free(b64_samlArt);
  g_free(relayState);

  return artifact;
}

LassoNode*
lasso_artifact_new_from_lares(const xmlChar *lares,
			      const xmlChar *relayState)
{
  LassoNode *artifact = NULL;
  gchar *byteCode, *identityProviderSuccinctID, *assertionHandle;
  gint ret;

  g_return_val_if_fail(lares != NULL, NULL);

  byteCode = (gchar *) g_new0(gchar, 5+1);
  identityProviderSuccinctID = (gchar *) g_new0(gchar, 20);
  assertionHandle = (gchar *) g_new0(gchar, 20+1);
  ret = lasso_artifact_split_samlArt((gchar*)lares, byteCode,
				     identityProviderSuccinctID,
				     assertionHandle);
  if (ret >= 0) {
    artifact = lasso_artifact_new((gchar*)lares,
				  byteCode, identityProviderSuccinctID,
				  assertionHandle,
				  (gchar*)relayState);
  }
  g_free(byteCode);
  g_free(identityProviderSuccinctID);
  g_free(assertionHandle);

  return artifact;
}
