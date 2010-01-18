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

#include <glib.h>
#include <glib/gprintf.h>

#include <lasso/xml/lib_scoping.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:complexType name="ScopingType">
  <xs:sequence>
    <xs:element name="ProxyCount" type="xs:nonNegativeInteger" minOccurs="0"/>
    <xs:element ref="IDPList" minOccurs="0"/>
  </xs:sequence>
</xs:complexType>
<xs:element name="Scoping" type="ScopingType"/>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_lib_scoping_set_proxyCount:
 * @node      : the pointer to <lib:Scoping/> node object
 * @proxyCount: the value of "ProxyCount" element (should be superior or equal
 * to 0).
 * 
 * Sets the "ProxyCount" element [optional].
 *
 * It's the upper limit on the number of proxying steps the requester wishes to
 * specify for the authentication request.
 **/
void
lasso_lib_scoping_set_proxyCount(LassoLibScoping *node,
				 gint proxyCount)
{
  gchar str[6];
  LassoNodeClass *class;

  g_assert(LASSO_IS_LIB_SCOPING(node));
  g_assert(proxyCount >= 0);

  g_sprintf(str, "%d", proxyCount);
  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProxyCount", str, FALSE);
}

/**
 * lasso_lib_scoping_set_idpList:
 * @node   : the pointer to <lib:Scoping/> node object
 * @idpList: the value of "IDPList" element
 * 
 * Sets the "IDPList" element [optional].
 *
 * It's an ordered list of identity providers which the requester prefers to
 * use in authenticating the Principal. This list is a suggestion only, and may
 * be ignored or added to by the recipient of the message.
 **/
void
lasso_lib_scoping_set_idpList(LassoLibScoping *node,
			      LassoLibIDPList *idpList)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_SCOPING(node));
  g_assert(LASSO_IS_LIB_IDP_LIST(idpList));

  class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(idpList), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_scoping_instance_init(LassoLibScoping *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "Scoping");
}

static void
lasso_lib_scoping_class_init(LassoLibScopingClass *klass)
{
}

GType lasso_lib_scoping_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibScopingClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_scoping_class_init,
      NULL,
      NULL,
      sizeof(LassoLibScoping),
      0,
      (GInstanceInitFunc) lasso_lib_scoping_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibScoping",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_lib_scoping_new:
 *
 * Creates a new <lib:Scoping/> node object.
 *
 * Specifies any preferences on the number and specific identifiers of
 * additional identity providers through which the authentication request may
 * be proxied. The requester may also choose not to include this element, in
 * which case, the recipient of the message MAY act as a proxy.
 * 
 * Return value: a new @LassoLibScoping
 **/
LassoNode* lasso_lib_scoping_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_SCOPING, NULL));
}
