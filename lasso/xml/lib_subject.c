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

#include <lasso/xml/lib_subject.h>

/*
The schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:complexType name="SubjectType">
  <xs:complexContent>
    <xs:extension base="saml:SubjectType">
      <xs:sequence>
        <xs:element ref="IDPProvidedNameIdentifier"/>
      </xs:sequence>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>
<xs:element name="Subject" type="SubjectType" substitutionGroup="saml:Subject"/>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_subject_set_idpProvidedNameIdentifier(LassoLibSubject *node,
						LassoLibIDPProvidedNameIdentifier *idpProvidedNameIdentifier)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_SUBJECT(node));
  g_assert(LASSO_IS_LIB_IDP_PROVIDED_NAME_IDENTIFIER(idpProvidedNameIdentifier));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(idpProvidedNameIdentifier), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

enum {
  LASSO_LIB_SUBJECT_USE_XSITYPE = 1
};

static void
lasso_lib_subject_set_property (GObject      *object,
				guint         property_id,
				const GValue *value,
				GParamSpec   *pspec)
{
  LassoLibSubject *self = LASSO_LIB_SUBJECT(object);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(object));

  switch (property_id) {
  case LASSO_LIB_SUBJECT_USE_XSITYPE:
    self->use_xsitype = g_value_get_boolean (value);
    if (self->use_xsitype == TRUE) {
      /* namespace and name were already set in parent class
	 LassoSamlAssertion */
      class->new_ns_prop(LASSO_NODE(object),
			 "type", "lib:SubjectType",
			 lassoXsiHRef, lassoXsiPrefix);
    }
    else {
      /* node name was already set in parent class LassoSamlAssertion
	 just change ns */
      class->set_ns(LASSO_NODE(object), lassoLibHRef, lassoLibPrefix);
    }
    break;
  default:
    /* We don't have any other property... */
    g_assert (FALSE);
    break;
  }
}

static void
lasso_lib_subject_instance_init(LassoLibSubject *node)
{
}

static void
lasso_lib_subject_class_init(LassoLibSubjectClass *g_class,
			     gpointer              g_class_data)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);
  GParamSpec *pspec;

  /* override parent class methods */
  gobject_class->set_property = lasso_lib_subject_set_property;

  pspec = g_param_spec_boolean ("use_xsitype",
				"use_xsitype",
				"using xsi:type",
				FALSE,
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE);
  g_object_class_install_property (gobject_class,
                                   LASSO_LIB_SUBJECT_USE_XSITYPE,
                                   pspec);
}

GType lasso_lib_subject_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibSubjectClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_subject_class_init,
      NULL,
      NULL,
      sizeof(LassoLibSubject),
      0,
      (GInstanceInitFunc) lasso_lib_subject_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT,
				       "LassoLibSubject",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_lib_subject_new(gboolean use_xsitype)
{
  LassoNode *node;

  node = LASSO_NODE(g_object_new(LASSO_TYPE_LIB_SUBJECT,
				 "use_xsitype", use_xsitype,
				 NULL));

  return node;
}
