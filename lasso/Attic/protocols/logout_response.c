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

  status_code = lasso_node_get_child(LASSO_NODE(response), "StatusCode",
				     NULL, NULL);
  if (status_code != NULL) {
    value = lasso_node_get_attr_value(status_code, "Value", &err);
    lasso_node_destroy(status_code);
    if (err != NULL) {
      message(G_LOG_LEVEL_WARNING, err->message);
      g_error_free(err);
      return (NULL);
    }
    else {
      return (value);
    }
  }
  else {
    message(G_LOG_LEVEL_WARNING, "No StatusCode element found in Response.\n");
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
lasso_logout_response_new(gchar               *providerID,
			  const gchar         *statusCodeValue,
			  LassoNode           *request,
			  lassoSignatureType   sign_type,
			  lassoSignatureMethod sign_method)
{
  LassoNode *response, *ss, *ssc;
  xmlChar *inResponseTo, *request_providerID, *request_relayState;
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
  lasso_samlp_response_abstract_set_issueInstant(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 (const xmlChar *)time);
  xmlFree(time);

  /* set the signature template */
  if (sign_type != lassoSignatureTypeNone) {
    lasso_samlp_response_abstract_set_signature_tmpl(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						     sign_type,
						     sign_method);
  }

  /* ProviderID */
  lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response),
					   providerID);
  
  inResponseTo = lasso_node_get_attr_value(request, "RequestID", NULL);
  lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 inResponseTo);
  xmlFree(inResponseTo);
  
  request_providerID = lasso_node_get_child_content(request, "ProviderID", NULL, NULL);
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      request_providerID);
  xmlFree(request_providerID);

  request_relayState = lasso_node_get_child_content(request, "RelayState", NULL, NULL);
  if (request_relayState != NULL) {
    lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response),
					     request_relayState);
    xmlFree(request_relayState);
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
  LassoNode *response, *ss, *ssc;
  xmlChar   *str;
  GData     *gd;
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));

  gd = lasso_query_to_dict(query);
  
  /* ResponseID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ResponseID"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response), str);
  
  /* MajorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response), str);
  
  /* MinorVersion */
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0));
  
  /* IssueInstant */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstant"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  lasso_samlp_response_abstract_set_issueInstant(LASSO_SAMLP_RESPONSE_ABSTRACT(response), str);
  
  /* InResponseTo */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "InResponseTo"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response), str);
  
  /* Recipient */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "Recipient"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response), str);
  
  /* ProviderID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response), str);
  
  /* StatusCode */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "Value"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(response);
    return (NULL);
  }
  ss = lasso_samlp_status_new();
  ssc = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(ssc),
				    str);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(ss),
				    LASSO_SAMLP_STATUS_CODE(ssc));
  lasso_lib_status_response_set_status(LASSO_LIB_STATUS_RESPONSE(response),
				       LASSO_SAMLP_STATUS(ss));
  lasso_node_destroy(ssc);
  lasso_node_destroy(ss);


  /* RelayState */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0);
  if (str != NULL)
    lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response), str);
  
  g_datalist_clear(&gd);

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
  if(envelope == NULL) {
    message(G_LOG_LEVEL_WARNING, "Error while parsing the soap msg\n");
    return(NULL);
  }

  lassoNode_response = lasso_node_get_child(envelope, "LogoutResponse",
					    NULL, NULL);
  if(lassoNode_response == NULL) {
    message(G_LOG_LEVEL_WARNING, "LogoutResponse node not found\n");
    return(NULL);
  }
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  lasso_node_destroy(lassoNode_response);

  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  lasso_node_destroy(envelope);
  
  return(response);
}

LassoNode*
lasso_logout_response_new_from_export(gchar               *buffer,
				      lassoNodeExportType  export_type)
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
    message(G_LOG_LEVEL_WARNING, "Invalid export type\n");
    return(NULL);
  }

  return(response);
}
