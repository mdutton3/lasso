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
#include <lasso/protocols/authn_request.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

gchar *
lasso_authn_request_get_protocolProfile(gchar *query)
{
  gchar *protocolProfile;

  protocolProfile = lasso_g_ptr_array_index(lasso_query_get_value(query, "ProtocolProfile"), 0);
  if (protocolProfile == NULL)
    protocolProfile = (gchar *)lassoLibProtocolProfileBrwsArt;

  return (protocolProfile);
}

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_authn_request_set_requestAuthnContext(LassoAuthnRequest *request,
					    GPtrArray         *authnContextClassRefs,
					    GPtrArray         *authnContextStatementRefs,
					    const xmlChar     *authnContextComparison)
{
  LassoNode *request_authn_context;
  gint i;

  g_return_if_fail (LASSO_IS_AUTHN_REQUEST(request));

  /*
    all arguments are optional
    however, we need at least one to create the RequestAuthnContext element
  */
  if (authnContextClassRefs || authnContextStatementRefs || authnContextComparison) {
    /* ok, we create a new RequestAuthnContext instance */
    request_authn_context = lasso_lib_request_authn_context_new();
    /* AuthnContextClassRefs */
    if (authnContextClassRefs != NULL) {
      if (authnContextClassRefs->len > 0) {
	for(i=0; i<authnContextClassRefs->len; i++) {
	  lasso_lib_request_authn_context_add_authnContextClassRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context),
								   lasso_g_ptr_array_index(authnContextClassRefs, i));
	}
      }
    }
    /* AuthnContextStatementRefs */
    if (authnContextStatementRefs != NULL) {
      if (authnContextStatementRefs->len > 0) {
	for(i=0; i<authnContextStatementRefs->len; i++) {
	  lasso_lib_request_authn_context_add_authnContextStatementRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context),
								       lasso_g_ptr_array_index(authnContextStatementRefs, i));
	}
      }
    }
    /* AuthnContextComparison */
    if (authnContextComparison != NULL) {
      lasso_lib_request_authn_context_set_authnContextComparison(LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context),
								 authnContextComparison);
    }
    /* Add RequestAuthnContext in AuthnRequest */
    lasso_lib_authn_request_set_requestAuthnContext(LASSO_LIB_AUTHN_REQUEST(request),
						    LASSO_LIB_REQUEST_AUTHN_CONTEXT(request_authn_context));
    lasso_node_destroy(request_authn_context);
  }
}

void
lasso_authn_request_set_scoping(LassoAuthnRequest *request,
				gint               proxyCount)
{
  LassoNode *scoping;

  g_return_if_fail (LASSO_IS_AUTHN_REQUEST(request));

  /* create a new Scoping instance */
  scoping = lasso_lib_scoping_new();
  /* ProxyCount */
  lasso_lib_scoping_set_proxyCount(LASSO_LIB_SCOPING(scoping), proxyCount);
  /* FIXME : set IDPList here */
  lasso_lib_authn_request_set_scoping(LASSO_LIB_AUTHN_REQUEST(request),
				      LASSO_LIB_SCOPING(scoping));
  lasso_node_destroy(scoping);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_request_instance_init(LassoAuthnRequest *request)
{
}

static void
lasso_authn_request_class_init(LassoAuthnRequestClass *class)
{
}

GType lasso_authn_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_request_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnRequest),
      0,
      (GInstanceInitFunc) lasso_authn_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHN_REQUEST,
				       "LassoAuthnRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authn_request_new(const xmlChar        *providerID,
			lassoSignatureType    sign_type,
			lassoSignatureMethod  sign_method)
{
  LassoNode *request;
  xmlChar   *id, *time;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_REQUEST, NULL));
  
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
  /* Signature template */
  if (sign_type != lassoSignatureTypeNone) {
    lasso_samlp_request_abstract_set_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						    sign_type,
						    sign_method,
						    id);
  }
  /* ProviderID */
  lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request),
					 providerID);

  return (request);
}

LassoNode*
lasso_authn_request_new_from_export(gchar               *buffer,
				    lassoNodeExportType  export_type)
{
  LassoNode *request = NULL, *authn_context = NULL, *scoping;
  LassoNode *request_node, *soap_node;
  GData     *gd;
  xmlChar   *str, *buffer_decoded;
  gchar     *export;
  GPtrArray *array;
  gint       i;

  g_return_val_if_fail(buffer != NULL, NULL);

  request = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_REQUEST, NULL));

  switch (export_type) {
  case lassoNodeExportTypeXml:
    lasso_node_import(request, buffer);
    break;
  case lassoNodeExportTypeQuery:
    gd = lasso_query_to_dict(buffer);

    /* RequestID */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RequestID"), 0);
    if (str != NULL)
      lasso_samlp_request_abstract_set_requestID(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						 str);
    else {
      g_datalist_clear(&gd);
      g_object_unref(request);
      return (NULL);
    }

    /* MajorVersion */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MajorVersion"), 0);
    if (str != NULL)
      lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						    str);
    else
      lasso_samlp_request_abstract_set_majorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						    lassoLibMajorVersion);
    
    /* MinorVersion */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "MinorVersion"), 0);
    if (str != NULL)
      lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						    str);
    else
      lasso_samlp_request_abstract_set_minorVersion(LASSO_SAMLP_REQUEST_ABSTRACT(request), 
						    lassoLibMinorVersion);
    
    /* IssueInstant */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IssueInstant"), 0);
    if (str != NULL) {
      lasso_samlp_request_abstract_set_issueInstant(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						    str);
    }
    else {
      g_datalist_clear(&gd);
      g_object_unref(request);
      return (NULL);
    }
    
    /* ProviderID */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProviderID"), 0);
    if (str != NULL)
      lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(request), str);
    else {
      g_datalist_clear(&gd);
      g_object_unref(request);
      return (NULL);
    }
    
    /* NameIDPolicy */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "NameIDPolicy"), 0);
    if (str != NULL)
      lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(request), str);
    
    /* ForceAuthn */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0);
    if (str != NULL){
      if(!strcmp(str, "true"))
	lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(request), TRUE);
      else if(!strcmp(str, "false"))
	lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(request), FALSE);
    }
    
    /* IsPassive */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0);
    if (str != NULL){
      if(!strcmp(str, "true"))
	lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(request), TRUE);
      else
	lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(request), FALSE);
    }
    
    /* ProtocolProfile */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProtocolProfile"), 0);
    if (str != NULL)
      lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(request), str);
    
    /* AssertionConsumerServiceID */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AssertionConsumerServiceID"), 0);
    if (str != NULL)
      lasso_lib_authn_request_set_assertionConsumerServiceID(LASSO_LIB_AUTHN_REQUEST(request), str);
    
    /* AuthnContext */
    array = (GPtrArray *)g_datalist_get_data(&gd, "AuthnContextClassRef");
    if (array != NULL) {
      if (authn_context == NULL)
	authn_context = lasso_lib_request_authn_context_new();
      for(i=0; i<array->len; i++)
	lasso_lib_request_authn_context_add_authnContextClassRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								 lasso_g_ptr_array_index(array, i));
    }
    array = (GPtrArray *)g_datalist_get_data(&gd, "AuthnContextStatementRef");
    if (array != NULL) {
      if (authn_context == NULL)
	authn_context = lasso_lib_request_authn_context_new();
      for(i=0; i<array->len; i++)
	lasso_lib_request_authn_context_add_authnContextStatementRef(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								     lasso_g_ptr_array_index(array, i));
    }
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "AuthnContextComparison"), 0);
    if (str != NULL) {
      if (authn_context == NULL)
	authn_context = lasso_lib_request_authn_context_new();
      lasso_lib_request_authn_context_set_authnContextComparison(LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context),
								 str);
    }
    if (authn_context != NULL) {
      lasso_lib_authn_request_set_requestAuthnContext(LASSO_LIB_AUTHN_REQUEST(request),
						      LASSO_LIB_REQUEST_AUTHN_CONTEXT(authn_context));
      lasso_node_destroy(authn_context);
    }
    
    /* RelayState */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "RelayState"), 0);
    if (str != NULL) {
      lasso_lib_authn_request_set_relayState(LASSO_LIB_AUTHN_REQUEST(request), str);
    }
    
    /* Scoping
       FIXME -> IDPList */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ProxyCount"), 0);
    if (str != NULL) {
      /* create a new Scoping instance */
      scoping = lasso_lib_scoping_new();
      /* ProxyCount */
      lasso_lib_scoping_set_proxyCount(LASSO_LIB_SCOPING(scoping), atoi(str));
      lasso_lib_authn_request_set_scoping(LASSO_LIB_AUTHN_REQUEST(request),
					  LASSO_LIB_SCOPING(scoping));
      lasso_node_destroy(scoping);
    }
    
    /* consent */
    str = lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "consent"), 0);
    if (str != NULL) {
      lasso_lib_authn_request_set_consent(LASSO_LIB_AUTHN_REQUEST(request), str);
    }
    
    g_datalist_clear(&gd);
    break;
  case lassoNodeExportTypeBase64:
    buffer_decoded = xmlMalloc(strlen(buffer));
    xmlSecBase64Decode(buffer, buffer_decoded, strlen(buffer));
    lasso_node_import(request, buffer_decoded);
    xmlFree(buffer_decoded);
    break;
  case lassoNodeExportTypeSoap:
    soap_node = lasso_node_new_from_dump(buffer);
    request_node = lasso_node_get_child(soap_node, "AuthnRequest",
					lassoLibHRef, NULL);
    export = lasso_node_export(request_node);
    lasso_node_import(request, export);
    g_free(export);
    lasso_node_destroy(request_node);
    lasso_node_destroy(soap_node);
    break;
  }

  return (request);
}
