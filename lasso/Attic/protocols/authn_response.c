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

#include <lasso/protocols/authn_response.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

xmlChar *
lasso_authn_response_get_protocolProfile(xmlChar *query)
{
  xmlChar *protocolProfile;

  protocolProfile = lasso_g_ptr_array_index(lasso_query_get_value(query, "ProtocolProfile"), 0);
  if (protocolProfile == NULL)
    protocolProfile = lassoLibProtocolProfileArtifact;

  return (protocolProfile);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_authn_response_add_assertion(LassoAuthnResponse *response,
				   LassoAssertion     *assertion,
				   const xmlChar      *private_key_file,
				   const xmlChar      *certificate_file)
{
  xmlDocPtr doc;
  LassoNode *signature;

  /* FIXME : Signature */
  doc = xmlNewDoc("1.0"); // <---
  xmlAddChild((xmlNodePtr)doc,
	      LASSO_NODE_GET_CLASS(response)->get_xmlNode(response));

  signature = lasso_ds_signature_new(doc, xmlSecTransformRsaSha1Id);
  lasso_saml_assertion_set_signature(LASSO_SAML_ASSERTION(assertion),
				     LASSO_DS_SIGNATURE(signature)); 
  lasso_samlp_response_add_assertion(LASSO_SAMLP_RESPONSE(response),
				     LASSO_LIB_ASSERTION(assertion));
  lasso_ds_signature_sign(LASSO_DS_SIGNATURE(signature),
			  private_key_file,
			  certificate_file);
}

gboolean
lasso_authn_response_must_authenticate(LassoAuthnResponse *response,
				       gboolean            is_authenticated)
{
  GData    *gd;
  gboolean  must_authenticate = FALSE;
  /* default values for ForceAuthn and IsPassive */
  gboolean forceAuthn = FALSE;
  gboolean isPassive  = TRUE;
 
  gd = lasso_query_to_dict(LASSO_AUTHN_RESPONSE(response)->query);
  /* Get ForceAuthn and IsPassive */
  if (xmlStrEqual(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0), "true")) {
    forceAuthn = TRUE;
  }
  if (xmlStrEqual((xmlChar *)lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0), "false")) {
    isPassive = FALSE;
  }
 
  if ((forceAuthn == TRUE || is_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }
                                                                                                                          
  g_datalist_clear(&gd);
  return (must_authenticate);
}

gboolean
lasso_authn_response_verify_signature(LassoAuthnResponse *response,
				      xmlChar            *public_key_file,
				      xmlChar            *private_key_file)
{
  g_return_val_if_fail(LASSO_IS_AUTHN_RESPONSE(response), 0);

  LassoNode *status, *status_code;
  gboolean signature_status;

  signature_status = lasso_query_verify_signature(LASSO_AUTHN_RESPONSE(response)->query,
						  public_key_file,
						  private_key_file);

  /* Status & StatusCode */
  if (signature_status == 0 || signature_status == 2) {
    status = lasso_samlp_status_new();
    status_code = lasso_samlp_status_code_new();
    switch (signature_status) {
    case 0:
      lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
					lassoLibStatusCodeInvalidSignature);
      break;
    case 2:
      lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
					lassoLibStatusCodeUnsignedAuthnRequest);
      break;
    }
    lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				      LASSO_SAMLP_STATUS_CODE(status_code));
    lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				    LASSO_SAMLP_STATUS(status));
  }

  return (signature_status);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_response_instance_init(LassoAuthnResponse *response)
{
}

static void
lasso_authn_response_class_init(LassoAuthnResponseClass *class)
{
}

GType lasso_authn_response_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_response_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnResponse),
      0,
      (GInstanceInitFunc) lasso_authn_response_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHN_RESPONSE,
				       "LassoAuthnResponse",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authn_response_new(xmlChar       *query,
			 const xmlChar *providerID,
			 gboolean       signature_status,
			 gboolean       authentication_status)
{
  GData         *gd;
  LassoNode     *response, *status, *status_code;
  const xmlChar *nameIDPolicy;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE, NULL));

  gd = lasso_query_to_dict(query);
  LASSO_AUTHN_RESPONSE(response)->query = query;

  /* ResponseID */
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       (const xmlChar *)lasso_build_unique_id(32));
  /* MajorVersion */
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lassoLibMajorVersion);     
  /* MinorVersion */
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), 
						 lassoLibMinorVersion);
  /* IssueInstance */
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  lasso_get_current_time());

  /* ProviderID */
  lasso_lib_authn_response_set_providerID(LASSO_LIB_AUTHN_RESPONSE(response),
					  providerID);

  /* RelayState */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0) != NULL) {
    lasso_lib_authn_response_set_relayState(LASSO_LIB_AUTHN_RESPONSE(response),
					    lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0));
  }
  /* InResponseTo */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0) != NULL) {
    lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0));
    LASSO_AUTHN_RESPONSE(response)->requestID = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0);
  }

  /* consent */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0) != NULL) {
    lasso_lib_authn_response_set_consent(LASSO_LIB_AUTHN_RESPONSE(response),
					 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0));
  }  

  /* Recipient */
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0));

  /* Status & StatusCode */
  status = lasso_samlp_status_new();
  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    lassoSamlStatusCodeSuccess);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));
  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				  LASSO_SAMLP_STATUS(status));

  return (response);
}
