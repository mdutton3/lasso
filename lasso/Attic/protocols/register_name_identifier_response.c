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

#include <lasso/protocols/register_name_identifier_response.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNode*
lasso_register_name_identifier_response_new_from_query(gchar *query)
{
  LassoNode *response;
  xmlChar *relayState;
  GData *gd;
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE, NULL));

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

static LassoNode*
lasso_register_name_identifier_response_new_from_soap(gchar *buffer)
{
  LassoNode *response;
  LassoNode *envelope, *lassoNode_response;
  xmlNodePtr xmlNode_response;
  LassoNodeClass *class;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE, NULL));

  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_response = lasso_node_get_child(envelope, "RegisterNameIdentifierResponse",
					    lassoLibHRef, NULL);
  
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  lasso_node_destroy(lassoNode_response);

  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  lasso_node_destroy(envelope);
  
  return(response);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_register_name_identifier_response_instance_init(LassoRegisterNameIdentifierResponse *response)
{
}

static void
lasso_register_name_identifier_response_class_init(LassoRegisterNameIdentifierResponseClass *class)
{
}

GType lasso_register_name_identifier_response_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoRegisterNameIdentifierResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_register_name_identifier_response_class_init,
      NULL,
      NULL,
      sizeof(LassoRegisterNameIdentifierResponse),
      0,
      (GInstanceInitFunc) lasso_register_name_identifier_response_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE,
				       "LassoRegisterNameIdentifierResponse",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_register_name_identifier_response_new(gchar     *providerID,
					    gchar     *statusCodeValue,
					    LassoNode *request)
{
  /* FIXME : change request type */
  LassoNode *response, *ss, *ssc;
  xmlChar *inResponseTo, *request_providerID, *request_relayState;
  xmlChar *id, *time;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE, NULL));
  
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

LassoNode*
lasso_register_name_identifier_response_new_from_request_export(gchar               *buffer,
								lassoNodeExportType  export_type,
								gchar               *providerID,
								gchar               *statusCodeValue)
{
  LassoNode *request, *response;

  g_return_val_if_fail(buffer != NULL, NULL);

  request = lasso_register_name_identifier_request_new_from_export(buffer, export_type);

  if(request){
    message(G_LOG_LEVEL_ERROR, "Error while building RegisterNameIdentifierRequest\n");
    return(NULL);
  }

  response = lasso_register_name_identifier_response_new(providerID,
							 statusCodeValue,
							 request);

  return(response);
}

LassoNode*
lasso_register_name_identifier_response_new_from_export(gchar               *buffer,
							lassoNodeExportType  export_type)
{
  LassoNode *response;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeQuery:
    response = lasso_register_name_identifier_response_new_from_query(buffer);
    break;
  case lassoNodeExportTypeSoap:
    response = lasso_register_name_identifier_response_new_from_soap(buffer);
    break;
  default:
    message(G_LOG_LEVEL_ERROR, "Invalid export type\n");
    return(NULL);
  }

  return(response);
}
