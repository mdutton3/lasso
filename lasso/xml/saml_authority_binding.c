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

#include <lasso/xml/saml_authority_binding.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="AuthorityBinding" type="saml:AuthorityBindingType"/>
<complexType name="AuthorityBindingType">
  <attribute name="AuthorityKind" type="QName" use="required"/>
  <attribute name="Location" type="anyURI" use="required"/>
  <attribute name="Binding" type="anyURI" use="required"/>
</complexType>

*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_authority_binding_set_authorityKind(LassoSamlAuthorityBinding *node,
					       const xmlChar *authorityKind)
{
  g_assert(LASSO_IS_SAML_AUTHORITY_BINDING(node));
  g_assert(authorityKind != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "AuthorityKind", authorityKind);
}

void
lasso_saml_authority_binding_set_binding(LassoSamlAuthorityBinding *node,
					 const xmlChar *binding)
{
  g_assert(LASSO_IS_SAML_AUTHORITY_BINDING(node));
  g_assert(binding != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "Binding", binding);
}

void
lasso_saml_authority_binding_set_location(LassoSamlAuthorityBinding *node,
					  const xmlChar *location)
{
  g_assert(LASSO_IS_SAML_AUTHORITY_BINDING(node));
  g_assert(location != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "Location", location);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_authority_binding_instance_init(LassoSamlAuthorityBinding *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlAssertionHRef,
		lassoSamlAssertionPrefix);
  class->set_name(LASSO_NODE(node), "AuthorityBinding");
}

static void
lasso_saml_authority_binding_class_init(LassoSamlAuthorityBindingClass *klass)
{
}

GType lasso_saml_authority_binding_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlAuthorityBindingClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_authority_binding_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlAuthorityBinding),
      0,
      (GInstanceInitFunc) lasso_saml_authority_binding_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlAuthorityBinding",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_authority_binding_new:
 * 
 * Creates a new <saml:AuthorityBinding> node object.
 * 
 * Return value: the new @LassoSamlAuthorityBinding
 **/
LassoNode* lasso_saml_authority_binding_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_AUTHORITY_BINDING, NULL));
}
