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

#include <lasso/xml/lib_authentication_statement.h>

/*
The schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthenticationStatement" type="AuthenticationStatementType" substitutionGroup="saml:Statement"/>
<xs:complexType name="AuthenticationStatementType">
  <xs:complexContent>
    <xs:extension base="saml:AuthenticationStatementType">
      <xs:sequence>
        <xs:element ref="AuthnContext" minOccurs="0"/>
      </xs:sequence>
      <xs:attribute name="ReauthenticateOnOrAfter" type="xs:dateTime" use="optional"/>
      <xs:attribute name="SessionIndex" type="xs:string" use="optional"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_authentication_statement_set_authnContext(LassoLibAuthenticationStatement *node,
						    LassoLibAuthnContext *authnContext)
{
  g_assert(LASSO_IS_LIB_AUTHENTICATION_STATEMENT(node));
  g_assert(LASSO_IS_LIB_AUTHN_CONTEXT(authnContext));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(authnContext), FALSE);
}

void
lasso_lib_authentication_statement_set_reauthenticateOnOrAfter(LassoLibAuthenticationStatement *node,
							       const xmlChar *reauthenticateOnOrAfter)
{
  g_assert(LASSO_IS_LIB_AUTHENTICATION_STATEMENT(node));
  g_assert(reauthenticateOnOrAfter != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "ReauthenticateOnOrAfter", reauthenticateOnOrAfter);
}

void
lasso_lib_authentication_statement_set_sessionIndex(LassoLibAuthenticationStatement *node,
						    const xmlChar *sessionIndex)
{
  g_assert(LASSO_IS_LIB_AUTHENTICATION_STATEMENT(node));
  g_assert(sessionIndex != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "SessionIndex", sessionIndex);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_authentication_statement_instance_init(LassoLibAuthenticationStatement *instance)
{
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->set_name(node, "AuthenticationStatement");
  class->new_ns(node, "urn:liberty:iff:2003-08", "lib");
}

static void
lasso_lib_authentication_statement_class_init(LassoLibAuthenticationStatementClass *klass)
{
}

GType lasso_lib_authentication_statement_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibAuthenticationStatementClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_authentication_statement_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAuthenticationStatement),
      0,
      (GInstanceInitFunc) lasso_lib_authentication_statement_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT,
				       "LassoLibAuthenticationStatement",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_lib_authentication_statement_new:
 *
 * Creates a new <lib:AuthenticationStatement> node object.
 * 
 * Return value: the new @LassoLibAuthenticationStatement
 **/
LassoNode* lasso_lib_authentication_statement_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT, NULL));
}
