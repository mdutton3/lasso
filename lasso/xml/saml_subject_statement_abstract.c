/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
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

#include <lasso/xml/saml_subject_statement_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="SubjectStatement" type="saml:SubjectStatementAbstractType"/>
<complexType name="SubjectStatementAbstractType" abstract="true">
  <complexContent>
    <extension base="saml:StatementAbstractType">
      <sequence>
        <element ref="saml:Subject"/>
      </sequence>
    </extension>
  </complexContent>
</complexType>
*/

/*****************************************************************************/
/* publics methods                                                           */
/*****************************************************************************/

void
lasso_saml_subject_statement_abstract_set_subject(LassoSamlSubjectStatementAbstract *node,
						  LassoSamlSubject *subject)
{
  g_assert(LASSO_IS_SAML_SUBJECT_STATEMENT_ABSTRACT(node));
  g_assert(LASSO_IS_SAML_SUBJECT(subject));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(subject), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_subject_statement_abstract_instance_init(LassoSamlSubjectStatementAbstract *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  /* namespace herited from saml:StatementAbstract */
  class->set_name(LASSO_NODE(node), "SubjectStatementAbstract");
}

static void
lasso_saml_subject_statement_abstract_class_init(LassoSamlSubjectStatementAbstractClass *klass)
{
}

GType lasso_saml_subject_statement_abstract_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlSubjectStatementAbstractClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_subject_statement_abstract_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlSubjectStatementAbstract),
      0,
      (GInstanceInitFunc) lasso_saml_subject_statement_abstract_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAML_STATEMENT_ABSTRACT,
				       "LassoSamlSubjectStatementAbstract",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_subject_statement_abstract_new:
 * @name: the node's name. If @name is NULL or an empty string, default value
 * "SubjectStatementAbstract" will be used.
 * 
 * Creates a new <saml:SubjectStatementAbstract> node object.
 * 
 * Return value: the new @LassoSamlSubjectStatementAbstract
 **/
LassoNode* lasso_saml_subject_statement_abstract_new(const xmlChar *name)
{
  LassoNode *node;

  node = LASSO_NODE(g_object_new(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT, NULL));

  if (name && *name)
    LASSO_NODE_GET_CLASS(node)->set_name(node, name);

  return (node);
}
