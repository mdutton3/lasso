/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
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

#include <lasso/xml/saml_authentication_statement.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="AuthenticationStatement" type="saml:AuthenticationStatementType"/>
<complexType name="AuthenticationStatementType">
  <complexContent>
    <extension base="saml:SubjectStatementAbstractType">
      <sequence>
        <element ref="saml:SubjectLocality" minOccurs="0"/>
        <element ref="saml:AuthorityBinding" minOccurs="0" maxOccurs="unbounded"/>
      </sequence>
      <attribute name="AuthenticationMethod" type="anyURI" use="required"/>
      <attribute name="AuthenticationInstant" type="dateTime" use="required"/>
    </extension>
  </complexContent>
</complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_authentication_statement_add_authorityBinding(LassoSamlAuthenticationStatement *node,
							 LassoSamlAuthorityBinding *authorityBinding)
{
  g_assert(LASSO_IS_SAML_AUTHENTICATION_STATEMENT(node));
  g_assert(LASSO_IS_SAML_AUTHORITY_BINDING(authorityBinding));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(authorityBinding), TRUE);
}

void
lasso_saml_authentication_statement_set_authenticationInstant(LassoSamlAuthenticationStatement *node,
							      const xmlChar *authenticationInstant)
{
  g_assert(LASSO_IS_SAML_AUTHENTICATION_STATEMENT(node));
  g_assert(authenticationInstant != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "AuthenticationInstant", authenticationInstant);
}

void
lasso_saml_authentication_statement_set_authenticationMethod(LassoSamlAuthenticationStatement *node,
							     const xmlChar *authenticationMethod)
{
  g_assert(LASSO_IS_SAML_AUTHENTICATION_STATEMENT(node));
  g_assert(authenticationMethod != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "AuthenticationMethod", authenticationMethod);
}

void
lasso_saml_authentication_statement_set_subjectLocality(LassoSamlAuthenticationStatement *node,
							LassoSamlSubjectLocality *subjectLocality)
{
  g_assert(LASSO_IS_SAML_AUTHENTICATION_STATEMENT(node));
  g_assert(LASSO_IS_SAML_SUBJECT_LOCALITY(subjectLocality));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(subjectLocality), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_authentication_statement_instance_init(LassoSamlAuthenticationStatement *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  /* namespace herited from SubjectStatementAbstract -> StatementAbstract */
  class->set_name(LASSO_NODE(node), "AuthenticationStatement");
}

static void
lasso_saml_authentication_statement_class_init(LassoSamlAuthenticationStatementClass *klass)
{
}

GType lasso_saml_authentication_statement_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlAuthenticationStatementClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_authentication_statement_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlAuthenticationStatement),
      0,
      (GInstanceInitFunc) lasso_saml_authentication_statement_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
				       "LassoSamlAuthenticationStatement",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_authentication_statement_new:
 *
 * Creates a new <saml:AuthenticationStatement> node object.
 * 
 * Return value: the new @LassoSamlAuthenticationStatement
 **/
LassoNode* lasso_saml_authentication_statement_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT, NULL));
}
