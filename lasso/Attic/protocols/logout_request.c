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

#include <lasso/protocols/logout_request.h>
#include <lasso/xml/saml_name_identifier.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_logout_request_instance_init(LassoLogoutRequest *request)
{
}

static void
lasso_logout_request_class_init(LassoLogoutRequestClass *class)
{
}

GType lasso_logout_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLogoutRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_logout_request_class_init,
      NULL,
      NULL,
      sizeof(LassoLogoutRequest),
      0,
      (GInstanceInitFunc) lasso_logout_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_LOGOUT_REQUEST,
				       "LassoLogoutRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode *
lasso_logout_request_new(const xmlChar *providerID,
			 const xmlChar *nameIdentifier,
			 const xmlChar *nameQualifier,
			 const xmlChar *format)
{
  LassoNode *request, *identifier;
  
  request = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_REQUEST, NULL));
  
  /* RequestID */
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					     (const xmlChar *)lasso_build_unique_id(32));
  /* MajorVersion */
  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						lassoLibMajorVersion);
  /* MinorVersion */
  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						   lassoLibMinorVersion);
  /* IssueInstant */
  lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						 lasso_get_current_time());
  /* ProviderID */
  lasso_lib_logout_request_set_providerID(LASSO_LIB_LOGOUT_REQUEST(request),
					  providerID);
  
  identifier = lasso_saml_name_identifier_new(nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier),
					       nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier), format);
  
  lasso_lib_logout_request_set_nameIdentifier(LASSO_LIB_LOGOUT_REQUEST(request),
					      LASSO_SAML_NAME_IDENTIFIER(identifier));
  
  return(request);
}

LassoNode *
lasso_logout_request_new_from_query(const xmlChar *query)
{
  LassoNode *request, *identifier;
  xmlChar *str;
  GData *gd;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_REQUEST, NULL));

  gd = lasso_query_to_dict(query);
  
  /* RequestID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0);
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* MajorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0);
  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* MinorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0);
  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* IssueInstant */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstance"), 0);
  lasso_samlp_request_abstract_set_issueInstance(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* ProviderID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0);
  lasso_lib_logout_request_set_providerID(LASSO_LIB_LOGOUT_REQUEST(request), str);
  
  /* NameIdentifier */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIdentifier"), 0);
  identifier = lasso_saml_name_identifier_new(str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameQualifier"), 0);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier), str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "Format"), 0);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier), str);
     
  lasso_lib_logout_request_set_nameIdentifier(LASSO_LIB_LOGOUT_REQUEST(request), LASSO_SAML_NAME_IDENTIFIER(identifier));
  
  /* RelayState */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0);
  if (str != NULL)
    lasso_lib_logout_request_set_relayState(LASSO_LIB_LOGOUT_REQUEST(request), str);
  
  /* SessionIndex */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SessionIndex"), 0);
  if (str != NULL)
    lasso_lib_logout_request_set_sessionIndex(LASSO_SAML_NAME_IDENTIFIER(identifier), (const xmlChar *)str);
  
  /* consent */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0);
  if (str != NULL)
    lasso_lib_logout_request_set_consent(LASSO_LIB_LOGOUT_REQUEST(request), str);

  g_datalist_clear(&gd);

  return(request);
}

LassoNode *
lasso_logout_request_new_from_soap(const xmlChar *buffer)
{
  LassoNode *request;
  LassoNode *envelope, *lassoNode_request;
  xmlNodePtr xmlNode_request;
  LassoNodeClass *class;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_LOGOUT_REQUEST, NULL));

  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_request = lasso_node_get_child(envelope, "LogoutRequest");
  
  class = LASSO_NODE_GET_CLASS(lassoNode_request);
  xmlNode_request = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_request)), 1);
  
  class = LASSO_NODE_GET_CLASS(request);
  class->set_xmlNode(LASSO_NODE(request), xmlNode_request);
  g_object_unref(envelope);
  
  return(request);
}
