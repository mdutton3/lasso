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

#include <lasso/protocols/response.h>

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
lasso_response_instance_init(LassoResponse *response)
{
}

static void
lasso_response_class_init(LassoResponseClass *class)
{
}

GType lasso_response_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_response_class_init,
      NULL,
      NULL,
      sizeof(LassoResponse),
      0,
      (GInstanceInitFunc) lasso_response_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAMLP_RESPONSE,
				       "LassoResponse",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_response_new()
{
  LassoNode *response;
  xmlChar   *id, *time;
  LassoNode *status, *status_code;

  response = lasso_samlp_response_new();

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

  /* Add Status */
  status = lasso_samlp_status_new();
  status_code = lasso_samlp_status_code_new();
  lasso_samlp_status_code_set_value(LASSO_SAMLP_STATUS_CODE(status_code), lassoSamlStatusCodeSuccess);
  lasso_samlp_status_set_statusCode(LASSO_SAMLP_STATUS(status), LASSO_SAMLP_STATUS_CODE(status_code));
  lasso_samlp_response_set_status(LASSO_SAMLP_RESPONSE(response), LASSO_SAMLP_STATUS(status));
  lasso_node_destroy(status_code);
  lasso_node_destroy(status);

  return (response);
}

LassoNode*
lasso_response_new_from_export(gchar               *buffer,
			       lassoNodeExportType  export_type)
{
  LassoNode *response = NULL, *soap_node, *response_node;
  gchar *export;

  g_return_val_if_fail(buffer != NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_RESPONSE, NULL));

  switch (export_type) {
  case lassoNodeExportTypeXml:
    lasso_node_import(response, buffer);
    break;
  case lassoNodeExportTypeBase64:
  case lassoNodeExportTypeQuery:
    break;
  case lassoNodeExportTypeSoap:
    soap_node = lasso_node_new_from_dump(buffer);
    response_node = lasso_node_get_child(soap_node, "Response",
					 lassoSamlProtocolHRef, NULL);
    export = lasso_node_export(response_node);
    lasso_node_import(response, export);
    g_free(export);
    lasso_node_destroy(response_node);
    lasso_node_destroy(soap_node);
    break;
  }

  return (response);
}
