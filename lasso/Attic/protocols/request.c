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

#include <lasso/xml/samlp_request.h>
#include <lasso/protocols/request.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_request_instance_init(LassoRequest *request)
{
}

static void
lasso_request_class_init(LassoRequestClass *class)
{
}

GType lasso_request_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoRequestClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_request_class_init,
      NULL,
      NULL,
      sizeof(LassoRequest),
      0,
      (GInstanceInitFunc) lasso_request_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAMLP_REQUEST,
				       "LassoRequest",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_request_new(const xmlChar *assertionArtifact)
{
  LassoNode *request;
  xmlChar   *id, *time;

  request = LASSO_NODE(g_object_new(LASSO_TYPE_REQUEST, NULL));
  
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

  /* Signature template with X509
     FIXME: signature method */
  lasso_samlp_request_abstract_set_signature_tmpl(LASSO_SAMLP_REQUEST_ABSTRACT(request),
						  lassoSignatureTypeWithX509,
						  lassoSignatureMethodRsaSha1,
						  NULL);

  /* AssertionArtifact */
  lasso_samlp_request_set_assertionArtifact(LASSO_SAMLP_REQUEST(request),
					    assertionArtifact);
  
  return request;
}

LassoNode*
lasso_request_new_from_export(gchar               *buffer,
			      lassoNodeExportType  export_type)
{
  LassoNode *request=NULL, *soap_node, *request_node;
  gchar *export;

  g_return_val_if_fail(buffer != NULL, NULL);

  request = LASSO_NODE(g_object_new(LASSO_TYPE_REQUEST, NULL));

  switch (export_type) {
  case lassoNodeExportTypeXml:
    lasso_node_import(request, buffer);
    break;
  case lassoNodeExportTypeQuery:
  case lassoNodeExportTypeBase64:
    break;
  case lassoNodeExportTypeSoap:
    soap_node = lasso_node_new_from_dump(buffer);
    request_node = lasso_node_get_child(soap_node, "Request",
					lassoSamlProtocolHRef, NULL);
    export = lasso_node_export(request_node);
    lasso_node_import(request, export);
    g_free(export);
    lasso_node_destroy(request_node);
    lasso_node_destroy(soap_node);
    break;
  }

  return request;
}
