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

#include <lasso/protocols/authn_request_envelope.h>

/*****************************************************************************/
/* functions                                                                 */
/*****************************************************************************/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

LassoNode *lasso_authn_request_envelope_get_authnRequest(LassoAuthnRequestEnvelope *request)
{
  g_return_val_if_fail(LASSO_IS_AUTHN_REQUEST_ENVELOPE(request), NULL);

  return lasso_node_get_child(LASSO_NODE(request), "AuthnRequest", NULL, NULL);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_authn_request_envelope_instance_init(LassoAuthnRequestEnvelope *request)
{
}

static void
lasso_authn_request_envelope_class_init(LassoAuthnRequestEnvelopeClass *class)
{
}

GType lasso_authn_request_envelope_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoAuthnRequestEnvelopeClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_authn_request_envelope_class_init,
      NULL,
      NULL,
      sizeof(LassoAuthnRequestEnvelope),
      0,
      (GInstanceInitFunc) lasso_authn_request_envelope_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE,
				       "LassoAuthnRequestEnvelope",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_authn_request_envelope_new(LassoAuthnRequest *authnRequest,
				 xmlChar           *providerID,
				 xmlChar           *assertionConsumerServiceURL)
{
  LassoNode *request;

  g_return_val_if_fail(LASSO_IS_AUTHN_REQUEST(authnRequest), NULL);
  g_return_val_if_fail(providerID != NULL, NULL);
  g_return_val_if_fail(assertionConsumerServiceURL != NULL, NULL);

  request = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_REQUEST_ENVELOPE, NULL));
  
  lasso_lib_authn_request_envelope_set_authnRequest(LASSO_LIB_AUTHN_REQUEST_ENVELOPE(request),
						    LASSO_LIB_AUTHN_REQUEST(authnRequest));
  lasso_lib_authn_request_envelope_set_providerID(LASSO_LIB_AUTHN_REQUEST_ENVELOPE(request),
						  providerID);
  lasso_lib_authn_request_envelope_set_assertionConsumerServiceURL(LASSO_LIB_AUTHN_REQUEST_ENVELOPE(request),
								   assertionConsumerServiceURL);

  return request;
}

LassoNode*
lasso_authn_request_envelope_new_from_export(gchar               *buffer,
					     lassoNodeExportType  export_type)
{
  LassoNode *request;
  xmlChar   *buffer_decoded;

  g_return_val_if_fail(buffer != NULL, NULL);

  request = LASSO_NODE(g_object_new(LASSO_TYPE_AUTHN_REQUEST_ENVELOPE, NULL));

  switch(export_type) {
  case lassoNodeExportTypeXml:
    lasso_node_import(request, buffer);
    break;
  case lassoNodeExportTypeBase64:
    buffer_decoded = xmlMalloc(strlen(buffer));
    xmlSecBase64Decode(buffer, buffer_decoded, strlen(buffer));
    lasso_node_import(request, buffer_decoded);
    xmlFree(buffer_decoded);
    break;
  default:
    message(G_LOG_LEVEL_WARNING, "Invalid export type : %d\n", export_type);
    g_free(request);
    request = NULL;
    break;
  }

  return request;
}
