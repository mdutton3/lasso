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

#include <lasso/xml/lib_assertion.h>

/*
Authentication assertions provided in an <AuthnResponse> element MUST be of
type AssertionType, which is an extension of saml:AssertionType, so that the
RequestID attribute from the original <AuthnRequest> MAY be included in the
InResponseTo attribute in the <Assertion> element. This is done because it is
not required that the <AuthnResponse> element itself be signed. Instead, the
individual <Assertion> elements contained MUST each be signed. Note that it is
optional for the InResponseTo to be present. Its absence indicates that the
<AuthnResponse> has been unilaterally sent by the identity provider without a
corresponding <AuthnRequest> message from the service provider. If the
attribute is present, it MUST be set to the RequestID of the original
<AuthnRequest>.

The schema fragment is as follows:

<xs:element name="Assertion" type="AssertionType" substitutionGroup="saml:Assertion" />
<xs:complexType name="AssertionType">
  <xs:complexContent>
    <xs:extension base="saml:AssertionType">
      <xs:attribute name="InResponseTo" type="xs:NCName" use="optional"/>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_lib_assertion_set_inResponseTo(LassoLibAssertion *node,
				     const xmlChar *inResponseTo)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_ASSERTION(node));
  g_assert(inResponseTo != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "InResponseTo", inResponseTo);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

enum {
  LASSO_LIB_ASSERTION_USE_XSITYPE = 1
};

static void
lasso_lib_assertion_set_property (GObject      *object,
				  guint         property_id,
				  const GValue *value,
				  GParamSpec   *pspec)
{
  LassoLibAssertion *self = LASSO_LIB_ASSERTION(object);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(object));

  switch (property_id) {
  case LASSO_LIB_ASSERTION_USE_XSITYPE:
    self->use_xsitype = g_value_get_boolean (value);
    if (self->use_xsitype == TRUE) {
      /* namespace and name were already set in parent class
	 LassoSamlAssertion */
      class->new_ns_prop(LASSO_NODE(object),
			 "type", "lib:AssertionType",
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
lasso_lib_assertion_instance_init(LassoLibAssertion *node)
{
}

static void
lasso_lib_assertion_class_init(LassoLibAssertionClass *g_class,
			       gpointer                g_class_data)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);
  GParamSpec *pspec;

  /* override parent class methods */
  gobject_class->set_property = lasso_lib_assertion_set_property;

  pspec = g_param_spec_boolean ("use_xsitype",
				"use_xsitype",
				"using xsi:type",
				FALSE,
				G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE);
  g_object_class_install_property (gobject_class,
                                   LASSO_LIB_ASSERTION_USE_XSITYPE,
                                   pspec);
}

GType lasso_lib_assertion_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibAssertionClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_assertion_class_init,
      NULL,
      NULL,
      sizeof(LassoLibAssertion),
      0,
      (GInstanceInitFunc) lasso_lib_assertion_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_SAML_ASSERTION,
				       "LassoLibAssertion",
				       &this_info, 0);
  }
  return this_type;
}

LassoNode*
lasso_lib_assertion_new(gboolean use_xsitype)
{
  LassoNode *node;

  node = LASSO_NODE(g_object_new(LASSO_TYPE_LIB_ASSERTION,
				 "use_xsitype", use_xsitype,
				 NULL));

  return (node);
}
