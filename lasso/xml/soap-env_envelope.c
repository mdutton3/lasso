/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
 *         Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/xml/soap-env_envelope.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_soap_env_envelope_add_body(LassoSoapEnvEnvelope *envelope,
				 LassoSoapEnvBody *body)
{
  g_assert(LASSO_IS_SOAP_ENV_ENVELOPE(envelope));
  g_assert(LASSO_IS_SOAP_ENV_BODY(body));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(envelope);
  class->add_child(LASSO_NODE(envelope),
		   LASSO_NODE(body),
		   FALSE);
}

LassoNode *
lasso_soap_env_envelope_get_body(LassoSoapEnvEnvelope *envelope)
{
     LassoNode *body;

     g_assert(LASSO_IS_SOAP_ENV_ENVELOPE(envelope));

     body = lasso_node_get_child(envelope, "Body");

     return(body);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_soap_env_envelope_instance_init(LassoSoapEnvEnvelope *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSoapEnvHRef,
		lassoSoapEnvPrefix);
  class->set_name(LASSO_NODE(node), "Envelope");
}

static void
lasso_soap_env_envelope_class_init(LassoSoapEnvEnvelopeClass *klass)
{
}

GType lasso_soap_env_envelope_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSoapEnvEnvelopeClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_soap_env_envelope_class_init,
      NULL,
      NULL,
      sizeof(LassoSoapEnvEnvelope),
      0,
      (GInstanceInitFunc) lasso_soap_env_envelope_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE ,
				       "LassoSoapEnvEnvelope",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_soap_env_envelope_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_SOAP_ENV_ENVELOPE,
				 NULL));
}
