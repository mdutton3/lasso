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

#include <lasso/xml/saml_subject_confirmation.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="SubjectConfirmation" type="saml:SubjectConfirmationType"/>
<complexType name="SubjectConfirmationType">
  <sequence>
    <element ref="saml:ConfirmationMethod" maxOccurs="unbounded"/>
    <element ref="saml:SubjectConfirmationData" minOccurs="0"/>
    <element ref="ds:KeyInfo" minOccurs="0"/>
  </sequence>
</complexType>

<element name="SubjectConfirmationData" type="anyType"/>
<element name="ConfirmationMethod" type="anyURI"/>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_subject_confirmation_add_confirmationMethod(LassoSamlSubjectConfirmation *node,
						       const xmlChar *confirmationMethod)
{
  g_assert(LASSO_IS_SAML_SUBJECT_CONFIRMATION(node));
  g_assert(confirmationMethod != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node),
		   "ConfirmationMethod", confirmationMethod, TRUE);
}

void
lasso_saml_subject_confirmation_set_subjectConfirmationMethod(LassoSamlSubjectConfirmation *node,
							      const xmlChar *subjectConfirmationMethod)
{
  g_assert(LASSO_IS_SAML_SUBJECT_CONFIRMATION(node));
  g_assert(subjectConfirmationMethod != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node),
		   "SubjectConfirmationMethod", subjectConfirmationMethod,
		   FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_subject_confirmation_instance_init(LassoSamlSubjectConfirmation *instance)
{
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, "urn:oasis:names:tc:SAML:1.0:assertion", "saml");
  class->set_name(node, "SubjectConfirmation");
}

static void
lasso_saml_subject_confirmation_class_init(LassoSamlSubjectConfirmationClass *klass)
{
}

GType lasso_saml_subject_confirmation_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlSubjectConfirmationClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_subject_confirmation_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlSubjectConfirmation),
      0,
      (GInstanceInitFunc) lasso_saml_subject_confirmation_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlSubjectConfirmation",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_subject_confirmation_new:
 * 
 * Creates a new <saml:SubjectConfirmation> node object.
 * 
 * Return value: the new @LassoSamlSubjectConfirmation
 **/
LassoNode* lasso_saml_subject_confirmation_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_SUBJECT_CONFIRMATION, NULL));
}
