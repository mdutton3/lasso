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
#include <lasso/protocols/authn_response_envelope.h>

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
lasso_authn_response_envelope_new(LassoLibAuthnResponse *authnResponse,
				  const xmlChar        *assertionConsumerServiceURL)
{
  LassoNode *response;

  g_return_val_if_fail(LASSO_IS_LIB_AUTHN_RESPONSE(authnResponse), NULL);
  g_return_val_if_fail(assertionConsumerServiceURL!=NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, NULL));
  
  lasso_lib_authn_response_envelope_set_authnResponse(LASSO_LIB_AUTHN_RESPONSE_ENVELOPE(response), authnResponse);
  lasso_lib_authn_response_envelope_set_assertionConsumerServiceURL(LASSO_LIB_AUTHN_RESPONSE_ENVELOPE(response),
								    assertionConsumerServiceURL);

  return(response);
}

LassoNode*
lasso_authn_response_envelope_new_from_export(gchar               *buffer,
					     lassoNodeExportTypes export_type)
{
  LassoNode *response;
  xmlChar   *buffer_decoded;

  g_return_val_if_fail(buffer != NULL, NULL);

  response = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, NULL));

  switch(export_type){
  case lassoNodeExportTypeBase64:
    buffer_decoded = xmlMalloc(strlen(buffer));
    xmlSecBase64Decode(buffer, buffer_decoded, strlen(buffer));
    lasso_node_import(response, buffer_decoded);
    xmlFree(buffer_decoded);
  default:
    break;
  }

  return(response);
}
