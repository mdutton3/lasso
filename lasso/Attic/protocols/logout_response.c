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
lasso_logout_response_new(const xmlChar *providerID,
			  const xmlChar *statusCodeValue,
			  LassoNode     *request)
{
  LassoNode *response, *ss, *ssc;
  xmlChar *inResponseTo, *recipient, *relayState;
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));
  
  /* Set ONLY required elements/attributs */
  /* ResponseID */
  lasso_samlp_response_abstract_set_responseID(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					       (const xmlChar *)lasso_build_unique_id(32));
  /* MajorVersion */
  lasso_samlp_response_abstract_set_majorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lassoLibMajorVersion);
  /* MinorVersion */
  lasso_samlp_response_abstract_set_minorVersion(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 lassoLibMinorVersion);
  /* IssueInstant */
  lasso_samlp_response_abstract_set_issueInstance(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						  lasso_get_current_time());
  /* ProviderID */
  lasso_lib_status_response_set_providerID(LASSO_LIB_STATUS_RESPONSE(response),
					   providerID);
  
  inResponseTo = xmlNodeGetContent((xmlNodePtr)lasso_node_get_attr(request, "RequestID"));
  lasso_samlp_response_abstract_set_inResponseTo(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
						 inResponseTo);
  
  
  recipient = lasso_node_get_content(lasso_node_get_child(request, "ProviderID"));
  lasso_samlp_response_abstract_set_recipient(LASSO_SAMLP_RESPONSE_ABSTRACT(response),
					      recipient);
  
  relayState = lasso_node_get_content(lasso_node_get_child(request, "RelayState"));
  if (relayState != NULL)
    lasso_lib_status_response_set_relayState(LASSO_LIB_STATUS_RESPONSE(response),
					     relayState);
     
  ss = lasso_samlp_status_new();
  ssc = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(ssc),
				    statusCodeValue);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(ss),
				    LASSO_SAMLP_STATUS_CODE(ssc));
  lasso_lib_status_response_set_status(LASSO_LIB_STATUS_RESPONSE(response),
				       LASSO_SAMLP_STATUS(ss));
  
  return (response);
}

LassoNode *
lasso_logout_response_new_from_dump(const xmlChar *buffer)
{
  LassoNode *response;
  
  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));
  lasso_node_import(response, buffer);
  
  return (response);
}

// build a LogoutResponse from a query form LogoutResponse
LassoNode *
lasso_logout_response_new_from_query(const xmlChar *query)
{
  LassoNode *response;
  xmlChar *relayState, *consent;
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

// build a LogoutResponse from a query form LogoutRequest
LassoNode *
lasso_logout_response_new_from_request_query(const xmlChar *query,
					     const xmlChar *providerID,
					     const xmlChar *statusCodeValue)
{
  LassoNode *request, *response;

  request = lasso_logout_request_new_from_query(query);
  
  response = lasso_logout_response_new(providerID,
				       statusCodeValue,
				       request);

  return(response);
}

// build a LogoutRespose from a soap form LogoutRequest
LassoNode *
lasso_logout_response_new_from_request_soap(const xmlChar *buffer,
					    const xmlChar *providerID,
					    const xmlChar *statusCodeValue)
{
  LassoNode *request, *response;

  request = lasso_logout_request_new_from_soap(buffer);

  response = lasso_logout_response_new(providerID,
				       statusCodeValue,
				       request);

  return(response);
}

LassoNode *
lasso_logout_response_new_from_soap(const xmlChar *buffer)
{
  LassoNode *response;
  LassoNode *envelope, *lassoNode_response;
  xmlNodePtr xmlNode_response;
  LassoNodeClass *class;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_RESPONSE, NULL));

  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_response = lasso_node_get_child(envelope, "LogoutResponse");
     
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  
  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  g_object_unref(envelope);
  
  return(response);
}
