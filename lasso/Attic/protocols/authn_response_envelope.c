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
#include <lasso/protocols/authn_response_envelope.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

xmlChar *lasso_authn_response_envelope_get_assertionConsumerServiceURL(LassoAuthnResponseEnvelope *response)
{
  g_return_val_if_fail(LASSO_IS_AUTHN_RESPONSE_ENVELOPE(response), NULL);

  return lasso_node_get_child_content(LASSO_NODE(response), "AssertionConsumerServiceURL", NULL, NULL);
}

LassoNode* lasso_authn_response_envelope_get_authnResponse(LassoAuthnResponseEnvelope *response)
{
  g_return_val_if_fail(LASSO_IS_AUTHN_RESPONSE_ENVELOPE(response), NULL);
  
  return lasso_node_get_child(LASSO_NODE(response), "AuthnResponse", NULL, NULL);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_response_envelope_instance_init(LassoAuthnResponseEnvelope *response)
{
}

static void
lasso_authn_response_envelope_class_init(LassoAuthnResponseEnvelopeClass *class)
{
}

GType lasso_authn_response_envelope_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnResponseEnvelopeClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_response_envelope_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnResponseEnvelope),
      0,
      (GInstanceInitFunc) lasso_authn_response_envelope_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE,
				       "LassoAuthnResponseEnvelope",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authn_response_envelope_new(LassoAuthnResponse *authnResponse,
				  xmlChar            *assertionConsumerServiceURL)
{
  LassoNode *response;

  g_return_val_if_fail(LASSO_IS_AUTHN_RESPONSE(authnResponse), NULL);
  g_return_val_if_fail(assertionConsumerServiceURL!=NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, NULL));
  
  lasso_lib_authn_response_envelope_set_authnResponse(LASSO_LIB_AUTHN_RESPONSE_ENVELOPE(response),
						      LASSO_LIB_AUTHN_RESPONSE(authnResponse));
  lasso_lib_authn_response_envelope_set_assertionConsumerServiceURL(LASSO_LIB_AUTHN_RESPONSE_ENVELOPE(response),
								    assertionConsumerServiceURL);

  return response;
}

static LassoNode *
lasso_authn_response_envelope_new_from_soap(gchar *buffer)
{
  LassoNode *response;
  LassoNode *envelope, *lassoNode_response;
  xmlNodePtr xmlNode_response;
  LassoNodeClass *class;

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, NULL));

  envelope = lasso_node_new_from_dump(buffer);
  lassoNode_response = lasso_node_get_child(envelope, "AuthnResponseEnvelope", NULL, NULL);
  
  class = LASSO_NODE_GET_CLASS(lassoNode_response);
  xmlNode_response = xmlCopyNode(class->get_xmlNode(LASSO_NODE(lassoNode_response)), 1);
  lasso_node_destroy(lassoNode_response);

  class = LASSO_NODE_GET_CLASS(response);
  class->set_xmlNode(LASSO_NODE(response), xmlNode_response);
  lasso_node_destroy(envelope);
  
  return response;
}

LassoNode*
lasso_authn_response_envelope_new_from_export(gchar              *buffer,
					     lassoNodeExportType  export_type)
{
  LassoNode *response = NULL;
  xmlChar   *buffer_decoded;

  g_return_val_if_fail(buffer != NULL, NULL);

  switch(export_type){
  case lassoNodeExportTypeBase64:
    response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, NULL));
    buffer_decoded = xmlMalloc(strlen(buffer));
    xmlSecBase64Decode(buffer, buffer_decoded, strlen(buffer));
    lasso_node_import(response, buffer_decoded);
    xmlFree(buffer_decoded);
    break;
  case lassoNodeExportTypeSoap:
    response = lasso_authn_response_envelope_new_from_soap(buffer);
    break;
  default:
    message(G_LOG_LEVEL_CRITICAL, "Invalid export type\n");
    return NULL;
    break;
  }

  return response;
}
