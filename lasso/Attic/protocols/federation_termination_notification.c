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

#include <lasso/protocols/federation_termination_notification.h>
#include <lasso/xml/saml_name_identifier.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_federation_termination_notification_instance_init(LassoFederationTerminationNotification *request)
{
}

static void
lasso_federation_termination_notification_class_init(LassoFederationTerminationNotificationClass *class)
{
}

GType lasso_federation_termination_notification_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoFederationTerminationNotificationClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_federation_termination_notification_class_init,
      NULL,
      NULL,
      sizeof(LassoFederationTerminationNotification),
      0,
      (GInstanceInitFunc) lasso_federation_termination_notification_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION,
				       "LassoFederationTerminationNotification",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_federation_termination_notification_new(const xmlChar *providerID,
					      const xmlChar *nameIdentifier,
					      const xmlChar *nameQualifier,
					      const xmlChar *format,
					      lassoSignatureType   sign_type,
					      lassoSignatureMethod sign_method)
{
  LassoNode *request, *identifier;
  xmlChar *id, *time;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION, NULL));
  
  /* Set ONLY required elements/attributes */
  /* RequestID */
  id = lasso_build_unique_id(32);
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
					     (const xmlChar *)id);
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
						(const xmlChar *)time);
  xmlFree(time);

  /* set the signature template */
  if (sign_type != lassoSignatureTypeNone) {
    lasso_samlp_request_abstract_set_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						    sign_type,
						    sign_method,
						    NULL);
  }

  /* ProviderID */
  lasso_lib_federation_termination_notification_set_providerID(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(request),
					 providerID);

  identifier = lasso_saml_name_identifier_new(nameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier), nameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier), format);

  lasso_lib_federation_termination_notification_set_nameIdentifier(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(request),
								   LASSO_SAML_NAME_IDENTIFIER(identifier));
  lasso_node_destroy(identifier);

  return (request);
}

LassoNode *
lasso_federation_termination_notification_new_from_query(const gchar *query)
{
  LassoNode *notification, *identifier;
  xmlChar *str;
  GData *gd;
  
  notification = LASSO_NODE(g_object_new(LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION, NULL));
  
  gd = lasso_query_to_dict(query);
  
  /* RequestID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(notification), str);
  
  /* MajorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);    
  }
  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification), str);
  
  /* MinorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(notification), str);
  
  /* IssueInstant */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstant"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  lasso_samlp_request_abstract_set_issueInstant(LASSO_SAMLP_REQUEST_ABSTRACT(notification), str);
  
  /* ProviderID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  lasso_lib_federation_termination_notification_set_providerID(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification), str);
  
  /* NameIdentifier */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIdentifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  identifier = lasso_saml_name_identifier_new(str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameQualifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(identifier), str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "Format"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(notification);
    return (NULL);
  }
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(identifier), str);
  
  lasso_lib_federation_termination_notification_set_nameIdentifier(LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(notification),
								   LASSO_SAML_NAME_IDENTIFIER(identifier));
  
  lasso_node_destroy(identifier);

  return(notification);
}

LassoNode *
lasso_federation_termination_notification_new_from_soap(const gchar *buffer)
{
  LassoNode *notification;
  LassoNode *envelope, *lassoNode_notification;
  xmlNodePtr xmlNode_notification;
  LassoNodeClass *class;
  
  notification = LASSO_NODE(g_object_new(LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION, NULL));
  
  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_notification = lasso_node_get_child(envelope, "FederationTerminationNotification",
						lassoLibHRef, NULL);
  
  class = LASSO_NODE_GET_CLASS(lassoNode_notification);
  xmlNode_notification = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_notification)), 1);
  lasso_node_destroy(lassoNode_notification);
  
  class = LASSO_NODE_GET_CLASS(notification);
  class->set_xmlNode(LASSO_NODE(notification), xmlNode_notification);
  lasso_node_destroy(envelope);
  
  return(notification);
}


LassoNode*
lasso_federation_termination_notification_new_from_export(const gchar         *buffer,
							  lassoNodeExportType  export_type)
{
  LassoNode *notification;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeQuery:
    notification = lasso_federation_termination_notification_new_from_query(buffer);
    break;
  case lassoNodeExportTypeSoap:
    notification = lasso_federation_termination_notification_new_from_soap(buffer);
    break;
  default:
    return(NULL);
  }

  return(notification);
}
