/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/samlp_status.h>

/*
Schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<element name="Status" type="samlp:StatusType"/>
<complexType name="StatusType">
  <sequence>
    <element ref="samlp:StatusCode"/>
    <element ref="samlp:StatusMessage" minOccurs="0" maxOccurs="1"/>
    <element ref="samlp:StatusDetail" minOccurs="0"/>
  </sequence>
</complexType>

<element name="StatusMessage" type="string"/>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_samlp_status_set_statusCode(LassoSamlpStatus *node,
				  LassoSamlpStatusCode *statusCode) {
  g_assert(LASSO_IS_SAMLP_STATUS(node));
  g_assert(LASSO_IS_SAMLP_STATUS_CODE(statusCode));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE (statusCode), FALSE);
}

/* TODO
void
lasso_samlp_status_set_statusDetail(LassoSamlpStatus *node,
                              LassoSamlpStatusDetail *statusDetail)
{
}
*/

void
lasso_samlp_status_set_statusMessage(LassoSamlpStatus *node,
				     const xmlChar *statusMessage)
{
  g_assert(LASSO_IS_SAMLP_STATUS(node));
  g_assert(statusMessage != NULL);
  
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "StatusMessage", statusMessage, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_samlp_status_instance_init(LassoSamlpStatus *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlProtocolHRef,
		lassoSamlProtocolPrefix);
  class->set_name(LASSO_NODE(node), "Status");
}

static void
lasso_samlp_status_class_init(LassoSamlpStatusClass *klass)
{
}

GType lasso_samlp_status_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlpStatusClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_samlp_status_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlpStatus),
      0,
      (GInstanceInitFunc) lasso_samlp_status_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlpStatus",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_samlp_status_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAMLP_STATUS,
				 NULL));
}
