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

#include <lasso/protocols/register_name_identifier_request.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_register_name_identifier_request_rename_attributes_for_query(LassoRegisterNameIdentifierRequest *request)

{
  LassoNode *idpidentifier, *spidentifier, *oldidentifier;

  g_return_if_fail (LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST(request));

  idpidentifier = lasso_node_get_child(LASSO_NODE(request), "IDPProvidedNameIdentifier",
				       NULL, NULL);
  lasso_node_rename_prop(idpidentifier, "NameQualifier", "IDPNameQualifier");
  lasso_node_rename_prop(idpidentifier, "Format", "IDPFormat");
  lasso_node_destroy(idpidentifier);

  spidentifier = lasso_node_get_child(LASSO_NODE(request), "SPProvidedNameIdentifier",
				      NULL, NULL);
  lasso_node_rename_prop(spidentifier, "NameQualifier", "SPNameQualifier");
  lasso_node_rename_prop(spidentifier, "Format", "SPFormat");
  lasso_node_destroy(spidentifier);

  oldidentifier = lasso_node_get_child(LASSO_NODE(request), "OldProvidedNameIdentifier",
				       NULL, NULL);
  lasso_node_rename_prop(oldidentifier, "NameQualifier", "OldNameQualifier");
  lasso_node_rename_prop(oldidentifier, "Format", "OldFormat");
  lasso_node_destroy(oldidentifier);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_register_name_identifier_request_instance_init(LassoRegisterNameIdentifierRequest *request)
{
}

static void
lasso_register_name_identifier_request_class_init(LassoRegisterNameIdentifierRequestClass *class)
{
}

GType lasso_register_name_identifier_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoRegisterNameIdentifierRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_register_name_identifier_request_class_init,
      NULL,
      NULL,
      sizeof(LassoRegisterNameIdentifierRequest),
      0,
      (GInstanceInitFunc) lasso_register_name_identifier_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST,
				       "LassoRegisterNameIdentifierRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_register_name_identifier_request_new(const xmlChar *providerID,
					   const xmlChar *idpProvidedNameIdentifier,
					   const xmlChar *idpNameQualifier,
					   const xmlChar *idpFormat,
					   const xmlChar *spProvidedNameIdentifier,
					   const xmlChar *spNameQualifier,
					   const xmlChar *spFormat,
					   const xmlChar *oldProvidedNameIdentifier,
					   const xmlChar *oldNameQualifier,
					   const xmlChar *oldFormat)
{
  LassoNode *request, *idpidentifier, *spidentifier, *oldidentifier;
  xmlChar *id, *time;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, NULL));
  
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
  /* ProviderID */
  lasso_lib_register_name_identifier_request_set_providerID(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
							    providerID);

  /* idp provided name identifier is required */
  idpidentifier = lasso_lib_idp_provided_name_identifier_new(idpProvidedNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(idpidentifier), idpNameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(idpidentifier), idpFormat);
  lasso_lib_register_name_identifier_request_set_idpProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									   LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idpidentifier));
  lasso_node_destroy(idpidentifier);

  /* old provided name identifier is required */
  oldidentifier = lasso_lib_old_provided_name_identifier_new(oldProvidedNameIdentifier);
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(oldidentifier), oldNameQualifier);
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(oldidentifier), oldFormat);
  lasso_lib_register_name_identifier_request_set_oldProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									   LASSO_LIB_OLD_PROVIDED_NAME_IDENTIFIER(oldidentifier));
  lasso_node_destroy(oldidentifier);

  /* sp provided name identifier is optional */
  if (spProvidedNameIdentifier != NULL && spNameQualifier != NULL && spFormat != NULL) {
    spidentifier = lasso_lib_sp_provided_name_identifier_new(spProvidedNameIdentifier);
    lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(spidentifier), spNameQualifier);
    lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(spidentifier), spFormat);
    lasso_lib_register_name_identifier_request_set_spProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									    LASSO_LIB_SP_PROVIDED_NAME_IDENTIFIER(spidentifier));
    lasso_node_destroy(spidentifier);
  }

  return request;
}

static LassoNode *
lasso_register_name_identifier_request_new_from_query(const xmlChar *query)
{
  LassoNode *request, *idpidentifier, *spidentifier, *oldidentifier;
  xmlChar *str;
  GData *gd;
  
  request = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, NULL));

  gd = lasso_query_to_dict(query);
     
  /* RequestID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* MajorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0);
  lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* MinorVersion */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* IssueInstant */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstant"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_samlp_request_abstract_set_issueInstant(LASSO_SAMLP_REQUEST_ABSTRACT(request), str);
  
  /* ProviderID */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0);  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_lib_register_name_identifier_request_set_providerID(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request), str);
  
  /* RelayState */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0);
  if (str != NULL)
    lasso_lib_register_name_identifier_request_set_relayState(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request), str);
  
  /* IDPProvidedNameIdentifier */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IDPProvidedNameIdentifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  idpidentifier = lasso_lib_idp_provided_name_identifier_new(str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IDPNameQualifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(idpidentifier), str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IDPFormat"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(idpidentifier), str);
  
  lasso_lib_register_name_identifier_request_set_idpProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									   LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idpidentifier));
  lasso_node_destroy(idpidentifier);
  
  /* SPPProvidedNameIdentifier */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SPProvidedNameIdentifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  spidentifier = lasso_lib_sp_provided_name_identifier_new(str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SPNameQualifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(spidentifier), str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "SPFormat"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(spidentifier), str);
  
  lasso_lib_register_name_identifier_request_set_spProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									  LASSO_LIB_SP_PROVIDED_NAME_IDENTIFIER(spidentifier));
  lasso_node_destroy(spidentifier);
 
  /* OldPProvidedNameIdentifier */
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "OldProvidedNameIdentifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  oldidentifier = lasso_lib_old_provided_name_identifier_new(str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "OldNameQualifier"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_saml_name_identifier_set_nameQualifier(LASSO_SAML_NAME_IDENTIFIER(oldidentifier), str);
  str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "OldFormat"), 0);
  if (str == NULL) {
    g_datalist_clear(&gd);
    g_object_unref(request);
    return NULL;
  }
  lasso_saml_name_identifier_set_format(LASSO_SAML_NAME_IDENTIFIER(oldidentifier), str);
     
  lasso_lib_register_name_identifier_request_set_oldProvidedNameIdentifier(LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(request),
									   LASSO_LIB_OLD_PROVIDED_NAME_IDENTIFIER(oldidentifier));
  lasso_node_destroy(oldidentifier);
 
  g_datalist_clear(&gd);
  
  return request;
}

static LassoNode *
lasso_register_name_identifier_request_new_from_soap(const xmlChar *buffer)
{
  LassoNode *request;
  LassoNode *envelope, *lassoNode_request;
  xmlNodePtr xmlNode_request;
  LassoNodeClass *class;
  
  request = LASSO_NODE(g_object_new(LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, NULL));
  
  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_request = lasso_node_get_child(envelope, "RegisterNameIdentifierRequest",
					   lassoLibHRef, NULL);
  
  class = LASSO_NODE_GET_CLASS(lassoNode_request);
  xmlNode_request = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_request)), 1);
  lasso_node_destroy(lassoNode_request);

  class = LASSO_NODE_GET_CLASS(request);
  class->set_xmlNode(LASSO_NODE(request), xmlNode_request);
  lasso_node_destroy(envelope);
  
  return request;
}

LassoNode*
lasso_register_name_identifier_request_new_from_export(gchar               *buffer,
						       lassoNodeExportType  export_type)
{
  LassoNode *request;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeQuery:
    request = lasso_register_name_identifier_request_new_from_query(buffer);
    break;
  case lassoNodeExportTypeSoap:
    request = lasso_register_name_identifier_request_new_from_soap(buffer);
    break;
  default:
    message(G_LOG_LEVEL_WARNING, "Invalid export type\n");
    request = NULL;
  }

  return request;
}
