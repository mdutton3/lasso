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

#include <lasso/xml/lib_authn_context.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthnContext">
  <xs:complexType>
    <xs:sequence>
      <xs:element name="AuthnContextClassRef" type="xs:anyURI" minOccurs="0"/>
      <xs:choice>
        <xs:element ref="ac:AuthenticationContextStatement"/>
        <xs:element name="AuthnContextStatementRef" type="xs:anyURI"/>
      </xs:choice>
    </xs:sequence>
  </xs:complexType>
</xs:element>

From schema liberty-authentication-context-v1.2.xsd:
<xs:element name="AuthenticationContextStatement" type="AuthenticationContextStatementType">
  <xs:annotation>
    <xs:documentation>
      A particular assertion on an identity
      provider's part with respect to the authentication
      context associated with an authentication assertion. 
    </xs:documentation>
  </xs:annotation>
</xs:element>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_authn_context_set_authnContextClassRef(LassoLibAuthnContext *node,
						 const xmlChar *authnContextClassRef) {
  g_assert(LASSO_IS_LIB_AUTHN_CONTEXT(node));
  g_assert(authnContextClassRef != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AuthnContextClassRef",
		   authnContextClassRef, FALSE);
}

void
lasso_lib_authn_context_set_authnContextStatementRef(LassoLibAuthnContext *node,
						     const xmlChar *authnContextStatementRef) {
  g_assert(LASSO_IS_LIB_AUTHN_CONTEXT(node));
  g_assert(authnContextStatementRef != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "AuthnContextStatementRef",
		   authnContextStatementRef, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_authn_context_instance_init(LassoLibAuthnContext *authnContext)
{
  LassoNodeClass *object_class = LASSO_NODE_GET_CLASS(authnContext);

  object_class->new_ns(LASSO_NODE(authnContext), "urn:liberty:iff:2003-08", "lib");
  object_class->set_name(LASSO_NODE(authnContext), "AuthnContext");
}

static void
lasso_lib_authn_context_class_init(LassoLibAuthnContextClass *klass)
{
}

GType lasso_lib_authn_context_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibAuthnContextClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_authn_context_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAuthnContext),
      0,
      (GInstanceInitFunc) lasso_lib_authn_context_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibAuthnContext",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode* lasso_lib_authn_context_new() {
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_AUTHN_CONTEXT,
				 NULL));
}
