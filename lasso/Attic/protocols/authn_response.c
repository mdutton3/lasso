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

#include <string.h>
#include <xmlsec/base64.h>
#include <lasso/xml/debug.h>
#include <lasso/protocols/authn_response.h>

static void
lasso_authn_response_set_status(LassoAuthnResponse *response,
				const xmlChar      *statusCodeValue) {
  LassoNode *status, *status_code;

  status = lasso_samlp_status_new();

  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    statusCodeValue);

  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));

  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response),
				  LASSO_SAMLP_STATUS(status));
  lasso_node_destroy(status_code);
  lasso_node_destroy(status);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

xmlChar *
lasso_authn_response_get_status(LassoAuthnResponse *response) {
  LassoNode *status_code;
  xmlChar *value;
  GError *err = NULL;

  status_code = lasso_node_get_child(LASSO_NODE(response), "StatusCode",
				     NULL, NULL);
  if (status_code != NULL) {
    value = lasso_node_get_attr_value(status_code, "Value", &err);
    lasso_node_destroy(status_code);
    if (err != NULL) {
      message(G_LOG_LEVEL_ERROR, err->message);
      g_error_free(err);
      return (NULL);
    }
    else {
      return (value);
    }
  }
  else {
    message(G_LOG_LEVEL_ERROR, "No StatusCode element found in AuthnResponse.\n");
    return (NULL);
  }
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
lasso_authn_response_new(char *providerID,
			 LassoNode *request)
{
  LassoNode *response;
  xmlChar *id, *time, *content;
  
  g_return_val_if_fail(providerID != NULL, NULL);
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE, NULL));
  
  /* ResponseID */
  id = lasso_build_unique_id(32);
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       (const xmlChar *)id);
  xmlFree(id);
  
  /* MajorVersion */
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lassoLibMajorVersion);     
  
  /* MinorVersion */
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), 
						 lassoLibMinorVersion);

  /* IssueInstance */
  time = lasso_get_current_time();
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  (const xmlChar *)time);
  xmlFree(time);
  
  /* ProviderID */
  lasso_lib_authn_response_set_providerID(LASSO_LIB_AUTHN_RESPONSE(response),
					  providerID);
  
  /* RelayState */
  content = lasso_node_get_child_content(request, "RelayState", lassoLibHRef, NULL);
  if (content != NULL) {
    lasso_lib_authn_response_set_relayState(LASSO_LIB_AUTHN_RESPONSE(response),
					    content);
    xmlFree(content);
  }

  /* Status Code */
  lasso_authn_response_set_status(LASSO_AUTHN_RESPONSE(response), lassoSamlStatusCodeSuccess);
  
  return(response);
}

LassoNode*
lasso_authn_response_new_from_export(xmlChar             *buffer,
				     lassoNodeExportType  export_type)
{
  xmlChar *buffer_decoded;
  LassoNode *response = NULL;

  g_return_val_if_fail(buffer != NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE, NULL));

  switch (export_type) {
  case lassoNodeExportTypeXml:
    lasso_node_import(response, buffer);
    break;
  case lassoNodeExportTypeBase64:
    buffer_decoded = xmlMalloc(strlen(buffer));
    xmlSecBase64Decode(buffer, buffer_decoded, strlen(buffer));
    lasso_node_import(response, buffer_decoded);
    xmlFree(buffer_decoded);
    break;
  case lassoNodeExportTypeQuery:
  case lassoNodeExportTypeSoap:
    break;
  }

  return (response);
}
