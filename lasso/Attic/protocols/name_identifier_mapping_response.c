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

#include <lasso/protocols/name_identifier_mapping_response.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

gint
lasso_name_identifier_mapping_response_set_status_code_value(LassoNameIdentifierMappingResponse *response,
							     xmlChar                            *statusCodeValue)
{
  LassoNode *status, *status_code;

  g_return_val_if_fail(LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE(response), -1);

  status = lasso_samlp_status_new();

  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code),
				    statusCodeValue);

  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status),
				    LASSO_SAMLP_STATUS_CODE(status_code));

  lasso_lib_name_identifier_mapping_response_set_status(LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(response),
							LASSO_SAMLP_STATUS(status));
  lasso_node_destroy(status_code);
  lasso_node_destroy(status);

  return 0;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNode *
lasso_name_identifier_mapping_response_new_from_soap(const gchar *buffer)
{
  LassoNode *response;
  LassoNode *envelope, *lassoNode_response;
  xmlNodePtr xmlNode_response;
  LassoNodeClass *class;

  envelope = lasso_node_new_from_dump(buffer);
  if (LASSO_IS_NODE(envelope) == FALSE) {
    return NULL;
  }

  response = LASSO_NODE(g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL));
  lassoNode_response = lasso_node_get_child(envelope, "NameIdentifierMappingResponse",
					    lassoLibHRef, NULL);
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  lasso_node_destroy(lassoNode_response);
  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  lasso_node_destroy(envelope);
  
  return response;
}


static LassoNode *
lasso_name_identifier_mapping_response_new_from_xml(gchar *buffer)
{
  LassoNode *response;
  LassoNode *lassoNode_response;
  xmlNodePtr xmlNode_response;
  LassoNodeClass *class;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL));

  lassoNode_response = lasso_node_new_from_dump(buffer);
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  lasso_node_destroy(lassoNode_response);
  
  return response;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_name_identifier_mapping_response_instance_init(LassoNameIdentifierMappingResponse *response)
{
}

static void
lasso_name_identifier_mapping_response_class_init(LassoNameIdentifierMappingResponseClass *class)
{
}

GType lasso_name_identifier_mapping_response_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoNameIdentifierMappingResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_name_identifier_mapping_response_class_init,
      NULL,
      NULL,
      sizeof(LassoNameIdentifierMappingResponse),
      0,
      (GInstanceInitFunc) lasso_name_identifier_mapping_response_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE,
				       "LassoNameIdentifierMappingResponse",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_name_identifier_mapping_response_new(const xmlChar       *providerID,
					   const xmlChar       *statusCodeValue,
					   LassoNode           *request,
					   lassoSignatureType   sign_type,
					   lassoSignatureMethod sign_method)
{
  LassoNode *response, *ss, *ssc;
  xmlChar *inResponseTo, *request_providerID;
  xmlChar *id, *time;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, NULL));
  
  /* ResponseID */
  id = lasso_build_unique_id(32);
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       id);
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
						 time);
  xmlFree(time);

  /* ProviderID */
  lasso_lib_name_identifier_mapping_response_set_providerID(LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(response),
							    providerID);

  /* InResponseTo */
  inResponseTo = lasso_node_get_attr_value(request, "RequestID", NULL);
  lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 inResponseTo);
  xmlFree(inResponseTo);

  /* Recipient */
  request_providerID = lasso_node_get_child_content(request, "ProviderID", NULL, NULL);
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      request_providerID);
  xmlFree(request_providerID);

  /* Status / StatusCode / Value */
  ss = lasso_samlp_status_new();
  ssc = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(ssc),
				    statusCodeValue);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(ss),
				    LASSO_SAMLP_STATUS_CODE(ssc));

  lasso_lib_name_identifier_mapping_response_set_status(LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(response),
							LASSO_SAMLP_STATUS(ss));
  lasso_node_destroy(ssc);
  lasso_node_destroy(ss);

  return response;
}

LassoNode*
lasso_name_identifier_mapping_response_new_from_export(gchar               *buffer,
						       lassoNodeExportType  export_type)
{
  LassoNode *response;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeSoap:
    response = lasso_name_identifier_mapping_response_new_from_soap(buffer);
    break;
  case lassoNodeExportTypeXml:
    response = lasso_name_identifier_mapping_response_new_from_xml(buffer);
    break;
  default:
    message(G_LOG_LEVEL_WARNING, "Invalid export type\n");
    return NULL;
  }

  return response;
}
