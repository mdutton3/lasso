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

#include <lasso/xml/lib_logout_response.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="LogoutResponse" type="StatusResponseType"/>

*/

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_logout_response_instance_init(LassoLibLogoutResponse *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  /* namespace herited from lib:StatusResponse */
  class->set_name(LASSO_NODE(node), "LogoutResponse");
}

static void
lasso_lib_logout_response_class_init(LassoLibLogoutResponseClass *klass)
{
}

GType lasso_lib_logout_response_get_type() {
  static GType logout_response_type = 0;

  if (!logout_response_type) {
    static const GTypeInfo logout_response_info = {
      sizeof (LassoLibLogoutResponseClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_logout_response_class_init,
      NULL,
      NULL,
      sizeof(LassoLibLogoutResponse),
      0,
      (GInstanceInitFunc) lasso_lib_logout_response_instance_init,
    };
    
    logout_response_type = g_type_register_static(LASSO_TYPE_LIB_STATUS_RESPONSE,
						 "LassoLibLogoutResponse",
						 &logout_response_info, 0);
  }
  return logout_response_type;
}

LassoNode* lasso_lib_logout_response_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_LOGOUT_RESPONSE, NULL));
}
