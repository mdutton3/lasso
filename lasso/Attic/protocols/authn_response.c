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
/* public methods                                                            */
/*****************************************************************************/

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
  gint           status_code_value = 1;

  gd = lasso_query_to_dict(query);
  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE, NULL));

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
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "RelayState"), 0) != NULL) {
    lasso_lib_authn_response_set_relayState(LASSO_LIB_AUTHN_RESPONSE(response),
					    lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "RelayState"), 0));
  }
  /* InResponseTo */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "RequestID"), 0) != NULL) {
    lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						   lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "RequestID"), 0));
  }

  /* consent */
  if (lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "consent"), 0) != NULL) {
    lasso_lib_authn_response_set_consent(LASSO_LIB_AUTHN_RESPONSE(response),
					 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "consent"), 0));
  }  

  /* Recipient */
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "ProviderID"), 0));

  /* Status & StatusCode */
  /* StatusCode */
  if (authentication_status == TRUE) {
    nameIDPolicy = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&(gd), "NameIDPolicy"), 0);
    if (xmlStrEqual(nameIDPolicy, "none") || nameIDPolicy == NULL) {
      printf("no NameIDPolicy or none value\n");
      status_code_value = 0;
    }
  }
  else
    status_code_value = 0;

  /* Add Status */
  status = lasso_samlp_status_new();
  status_code = lasso_samlp_status_code_new();
  if (status_code_value == 0)
    lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code), lassoSamlStatusCodeRequestDenied);
  else
    lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code), lassoSamlStatusCodeSuccess);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status), LASSO_SAMLP_STATUS_CODE(status_code));
  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response), LASSO_SAMLP_STATUS(status));

  return (response);
}
