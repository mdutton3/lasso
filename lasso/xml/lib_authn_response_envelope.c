/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/lib_authn_response_envelope.h>



/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_authn_response_envelope_set_extension(LassoLibAuthnResponseEnvelope *node,
						LassoNode *extension)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE(node));
  g_assert(LASSO_NODE(extension));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE(extension), extension, FALSE);
}

void
lasso_lib_authn_response_envelope_set_authnResponse(LassoLibAuthnResponseEnvelope *node,
						    LassoLibAuthnResponse         *authnResponse_node)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE(node));
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE(authnResponse_node));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE(node), LASSO_NODE(authnResponse_node), FALSE);
}

void
lasso_lib_authn_response_envelope_set_assertionConsumerServiceURL(LassoLibAuthnResponseEnvelope *node,
								  const xmlChar                 *url)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE(node));
  g_assert(url != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AssertionConsumerServiceURL",
		   url, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_authn_response_envelope_instance_init(LassoLibAuthnResponseEnvelope *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "AuthnResponseEnvelope");
}

static void
lasso_lib_authn_response_envelope_class_init(LassoLibAuthnResponseEnvelopeClass *class)
{
}

GType lasso_lib_authn_response_envelope_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibAuthnResponseEnvelopeClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_authn_response_envelope_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAuthnResponseEnvelope),
      0,
      (GInstanceInitFunc) lasso_lib_authn_response_envelope_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibAuthnResponseEnvelope",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_authn_response_envelope_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE,
				 NULL));
}
