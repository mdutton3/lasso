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

#include <lasso/protocols/logout_response.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gchar*
lasso_logout_response_get_status_code_value(LassoLogoutResponse *response)
{
  LassoNode *status_code;
  xmlChar *value;
  GError *err = NULL;

  status_code = lasso_node_get_child(LASSO_NODE(response), "StatusCode", NULL);
  if (status_code != NULL) {
    value = lasso_node_get_attr_value(status_code, "Value", &err);
    lasso_node_destroy(status_code);
    if (err != NULL) {
      debug(ERROR, err->message);
      g_error_free(err);
      return (NULL);
    }
    else {
      return (value);
    }
  }
  else {
    debug(ERROR, "No StatusCode element found in Response.\n");
    return (NULL);
  }
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_response_instance_init(LassoLogoutResponse *response)
{
}

static void
lasso_logout_response_class_init(LassoLogoutResponseClass *class)
{
}

GType lasso_logout_response_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLogoutResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_logout_response_class_init,
      NULL,
      NULL,
      sizeof(LassoLogoutResponse),
      0,
      (GInstanceInitFunc) lasso_logout_response_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_LOGOUT_RESPONSE,
				       "LassoLogoutResponse",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_logout_response_new(gchar       *providerID,
			  const gchar *statusCodeValue,
			  LassoNode   *request)
{
  LassoNode *response, *ss, *ssc, *request_providerID, *request_relayState;
  xmlChar *inResponseTo, *recipient, *relayState;
  xmlChar *id, *time;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));
  
  /* Set ONLY required elements/attributes */
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
  /* IssueInstant */
  time = lasso_get_current_time();
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  (const xmlChar *)time);
  xmlFree(time);
  /* ProviderID */
  lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response),
					   providerID);
  
  inResponseTo = xmlNodeGetContent((xmlNodePtr)lasso_node_get_attr(request, "RequestID"));
  lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 inResponseTo);
  
  request_providerID = lasso_node_get_child(request, "ProviderID", NULL);
  recipient = lasso_node_get_content(request_providerID);
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      recipient);
  lasso_node_destroy(request_providerID);
  
  request_relayState = lasso_node_get_child(request, "RelayState", NULL);
  if (request_relayState != NULL) {
    relayState = lasso_node_get_content(request_relayState);
    lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response),
					     relayState);
    lasso_node_destroy(request_relayState);
  }

  ss = lasso_samlp_status_new();
  ssc = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(ssc),
				    statusCodeValue);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(ss),
				    LASSO_SAMLP_STATUS_CODE(ssc));
  lasso_lib_status_response_set_status(LASSO_LIB_STATUS_RESPONSE(response),
				       LASSO_SAMLP_STATUS(ss));
  lasso_node_destroy(ssc);
  lasso_node_destroy(ss);
  
  return (response);
}

LassoNode *
lasso_logout_response_new_from_dump(gchar *buffer)
{
  LassoNode *response;
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));
  lasso_node_import(response, buffer);
  
  return (response);
}

LassoNode *
lasso_logout_response_new_from_query(gchar *query)
{
  LassoNode *response;
  xmlChar *relayState;
  GData *gd;
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));

  gd = lasso_query_to_dict(query);
  
  /* ResponseID */
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ResponseID"), 0));
  
  /* MajorVersion */
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0));
  
  /* MinorVersion */
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0));
  
  /* IssueInstant */
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstance"), 0));
  
  /* InResponseTo */
  lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "InResponseTo"), 0));
  
  /* Recipient */
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "Recipient"), 0));
  
  /* ProviderID */
  lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response),
					   lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0));
  
  /* RelayState */
  relayState = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0);
  if (relayState != NULL)
    lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response), relayState);
  
  g_datalist_clear(&gd);

  return(response);
}

LassoNode *
lasso_logout_response_new_from_request_export(gchar                *buffer,
					      lassoNodeExportTypes  export_type,
					      gchar                *providerID,
					      gchar                *statusCodeValue)
{
  LassoNode *request, *response;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeQuery:
    request = lasso_logout_request_new_from_export(buffer, export_type);
    break;
  case lassoNodeExportTypeSoap:
    request = lasso_logout_request_new_from_export(buffer, export_type);
    break;
  default:
    debug(ERROR, "Unkown export type\n");
    return(NULL);
  }

  response = lasso_logout_response_new(providerID,
				       statusCodeValue,
				       request);

  return(response);
}

LassoNode *
lasso_logout_response_new_from_soap(gchar *buffer)
{
  LassoNode *response;
  LassoNode *envelope, *lassoNode_response;
  xmlNodePtr xmlNode_response;
  LassoNodeClass *class;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));

  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_response = lasso_node_get_child(envelope, "LogoutResponse", lassoLibHRef);
     
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  lasso_node_destroy(lassoNode_response);

  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  lasso_node_destroy(envelope);
  
  return(response);
}

LassoNode*
lasso_logout_response_new_from_export(gchar                *buffer,
				      lassoNodeExportTypes  export_type)
{
  LassoNode *response;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeQuery:
    response = lasso_logout_response_new_from_query(buffer);
    break;
  case lassoNodeExportTypeSoap:
    response = lasso_logout_response_new_from_soap(buffer);
    break;
  default:
    debug(ERROR, "Unknown export type\n");
    return(NULL);
  }

  return(response);
}
