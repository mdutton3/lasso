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

#include <lasso/xml/saml_name_identifier.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="NameIdentifier" type="saml:NameIdentifierType"/>
<complexType name="NameIdentifierType">
  <simpleContent>
    <extension base="string">
      <attribute name="NameQualifier" type="string" use="optional"/>
      <attribute name="Format" type="anyURI" use="optional"/>
    </extension>
  </simpleContent>
</complexType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_name_identifier_set_format(LassoSamlNameIdentifier *node,
				      const xmlChar *format)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_NAME_IDENTIFIER(node));
  g_assert(format != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "Format", format);
}

void
lasso_saml_name_identifier_set_nameQualifier(LassoSamlNameIdentifier *node,
					     const xmlChar *nameQualifier)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_SAML_NAME_IDENTIFIER(node));
  g_assert(nameQualifier != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "NameQualifier", nameQualifier);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_name_identifier_instance_init(LassoSamlNameIdentifier *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlAssertionHRef,
		lassoSamlAssertionPrefix);
  class->set_name(LASSO_NODE(node), "NameIdentifier");
}

static void
lasso_saml_name_identifier_class_init(LassoSamlNameIdentifierClass *klass)
{
}

GType lasso_saml_name_identifier_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlNameIdentifierClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_name_identifier_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlNameIdentifier),
      0,
      (GInstanceInitFunc) lasso_saml_name_identifier_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlNameIdentifier",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_name_identifier_new:
 * @content: the node content
 * 
 * Creates a new <saml:NameIdentifier> node object.
 * 
 * Return value: the new @LassoSamlNameIdentifier
 **/
LassoNode* lasso_saml_name_identifier_new(const xmlChar *content)
{
  LassoNode *node;

  g_assert(content != NULL);

  node = LASSO_NODE(g_object_new(LASSO_TYPE_SAML_NAME_IDENTIFIER, NULL));
  xmlNodeSetContent(LASSO_NODE_GET_CLASS(node)->get_xmlNode(node),
		    content);
  return node;
}
