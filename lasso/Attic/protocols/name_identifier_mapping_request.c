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

#include <lasso/protocols/name_identifier_mapping_request.h>
#include <lasso/xml/saml_name_identifier.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_name_identifier_mapping_request_instance_init(LassoNameIdentifierMappingRequest *request)
{
}

static void
lasso_name_identifier_mapping_request_class_init(LassoNameIdentifierMappingRequestClass *class)
{
}

GType lasso_name_identifier_mapping_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoNameIdentifierMappingRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_name_identifier_mapping_request_class_init,
      NULL,
      NULL,
      sizeof(LassoNameIdentifierMappingRequest),
      0,
      (GInstanceInitFunc) lasso_name_identifier_mapping_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST,
				       "LassoNameIdentifierMappingRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_name_identifier_mapping_request_new(const xmlChar       *providerID,
					  const xmlChar       *nameIdentifier,
					  const xmlChar       *nameQualifier,
					  const xmlChar       *format,
					  const xmlChar       *targetNameSpace,
					  lassoSignatureType   sign_type,
					  lassoSignatureMethod sign_method)
{
  LassoNode *request, *identifier;
  xmlChar *id, *time;

  g_return_val_if_fail(providerID != NULL, NULL);
  g_return_val_if_fail(nameIdentifier != NULL, NULL);
  g_return_val_if_fail(nameQualifier != NULL, NULL);
  g_return_val_if_fail(format != NULL, NULL);
  g_return_val_if_fail(targetNameSpace != NULL, NULL);

  request = LASSO_NODE(g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST, NULL));
  
  /* Set ONLY required elements/attributes */
  /* RequestID */
  id = lasso_build_unique_id(32);
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					     id);
  xmlFree(id);
  /* MajorVersion */
  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						lassoLibMajorVersion);
  /* MinorVersion */
  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						lassoLibMinorVersion);
  /* IssueInstant */
  time = lasso_get_current_time();
  lasso_samlp_request_abstract_set_issueInstant(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						time);
  xmlFree(time);
  /* ProviderID */
  lasso_lib_name_identifier_mapping_request_set_providerID(LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request),
							   providerID);

  /* NameIdentifier */
  identifier = lasso_saml_name_identifier_new(nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier),
					       nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier),
					format);

  lasso_lib_name_identifier_mapping_request_set_nameIdentifier(LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request),
							       LASSO_SAML_NAME_IDENTIFIER(identifier));
  lasso_node_destroy(identifier);

  /* Target name space */
  lasso_lib_name_identifier_mapping_request_set_targetNameSpace(LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(request),
								targetNameSpace);

  return request;
}

static LassoNode *
lasso_name_identifier_mapping_request_new_from_soap(const gchar *buffer)
{
  LassoNode *request;
  LassoNode *envelope, *lassoNode_request;
  xmlNodePtr xmlNode_request;
  LassoNodeClass *class;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST, NULL));

  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_request = lasso_node_get_child(envelope, "NameIdentifierMappingRequest",
					   lassoLibHRef, NULL);
  
  class = LASSO_NODE_GET_CLASS(lassoNode_request);
  xmlNode_request = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_request)), 1);
  lasso_node_destroy(lassoNode_request);

  class = LASSO_NODE_GET_CLASS(request);
  class->set_xmlNode(LASSO_NODE(request), xmlNode_request);
  lasso_node_destroy(envelope);
  
  return request;
}

static LassoNode *
lasso_name_identifier_mapping_request_new_from_xml(gchar *buffer)
{
  LassoNode *request;
  LassoNode *lassoNode_request;
  xmlNodePtr xmlNode_request;
  LassoNodeClass *class;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST, NULL));

  lassoNode_request = lasso_node_new_from_dump(buffer);
  class = LASSO_NODE_GET_CLASS(lassoNode_request);
  xmlNode_request = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_request)), 1);
  class = LASSO_NODE_GET_CLASS(request);
  class->set_xmlNode(LASSO_NODE(request), xmlNode_request);
  lasso_node_destroy(lassoNode_request);
  
  return request;
}

LassoNode*
lasso_name_identifier_mapping_request_new_from_export(gchar               *buffer,
						      lassoNodeExportType  export_type)
{
  LassoNode *request = NULL;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeSoap:
    request = lasso_name_identifier_mapping_request_new_from_soap(buffer);
    break;
  case lassoNodeExportTypeXml:
    request = lasso_name_identifier_mapping_request_new_from_xml(buffer);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Unsupported export type\n");
    break;
  }

  return request;
}
