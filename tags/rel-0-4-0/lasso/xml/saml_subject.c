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

#include <lasso/xml/saml_subject.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="Subject" type="saml:SubjectType"/>
<complexType name="SubjectType">
  <choice>
    <sequence>
      <element ref="saml:NameIdentifier"/>
      <element ref="saml:SubjectConfirmation" minOccurs="0"/>
    </sequence>
    <element ref="saml:SubjectConfirmation"/>
  </choice>
</complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_subject_set_nameIdentifier(LassoSamlSubject *node,
				      LassoSamlNameIdentifier *nameIdentifier)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_SUBJECT(node));
  g_assert(LASSO_IS_SAML_NAME_IDENTIFIER(nameIdentifier));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(nameIdentifier), FALSE);
}

void
lasso_saml_subject_set_subjectConfirmation(LassoSamlSubject *node,
					   LassoSamlSubjectConfirmation *subjectConfirmation)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_SUBJECT(node));
  g_assert(LASSO_IS_SAML_SUBJECT_CONFIRMATION(subjectConfirmation));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE (subjectConfirmation), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_subject_instance_init(LassoSamlSubject *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlAssertionHRef,
		lassoSamlAssertionPrefix);
  class->set_name(LASSO_NODE(node), "Subject");
}

static void
lasso_saml_subject_class_init(LassoSamlSubjectClass *klass) {
}

GType lasso_saml_subject_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlSubjectClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_subject_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlSubject),
      0,
      (GInstanceInitFunc) lasso_saml_subject_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlSubject",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_subject_new:
 * 
 * Creates a new <saml:Subject> node object.
 *
 * Return value: the new @LassoSamlSubject
 **/
LassoNode* lasso_saml_subject_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_SUBJECT, NULL));
}
