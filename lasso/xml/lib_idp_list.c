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

#include <lasso/xml/lib_idp_list.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="IDPList" type="IDPListType"/>
<xs:complexType name="IDPListType">
  <xs:sequence>
    <xs:element ref="IDPEntries"/>
    <xs:element ref="GetComplete" minOccurs="0"/>
  </xs:sequence>
</xs:complexType>

<xs:element name="GetComplete" type="xs:anyURI"/>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_lib_idp_list_set_getComplete:
 * @node: the pointer to <lib:IDPList/> node object
 * @getComplete: the value of "GetComplete" element.
 * 
 * Sets the "GetComplete" element [optional].
 *
 * If the identity provider list is not complete, this element may be included
 * with a URI that points to where the complete list can be retrieved.
 **/
void
lasso_lib_idp_list_set_getComplete(LassoLibIDPList *node,
				   const xmlChar *getComplete)
{
  g_assert(LASSO_IS_LIB_IDP_LIST(node));
  g_assert(getComplete != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "GetComplete", getComplete, FALSE);
}

/**
 * lasso_lib_idp_list_set_idpEntries:
 * @node: the pointer to <lib:IDPList/> node object
 * @idpEntries: the pointer to <lib:IDPEntries/> node object
 * 
 * Set the "IDPEntries" element [required].
 *
 * It contains a list of identity provider entries.
 **/
void
lasso_lib_idp_list_set_idpEntries(LassoLibIDPList *node,
				  LassoLibIDPEntries *idpEntries)
{
  g_assert(LASSO_IS_LIB_IDP_LIST(node));
  g_assert(LASSO_IS_LIB_IDP_ENTRIES(idpEntries));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(idpEntries), FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_idp_list_instance_init(LassoLibIDPList *instance)
{
  LassoNode *node = (LassoNode *)instance;
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, "urn:liberty:iff:2003-08", "lib");
  class->set_name(node, "IDPList");
}

static void
lasso_lib_idp_list_class_init(LassoLibIDPListClass *klass)
{
}

GType lasso_lib_idp_list_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibIDPListClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_idp_list_class_init,
      NULL,
      NULL,
      sizeof(LassoLibIDPList),
      0,
      (GInstanceInitFunc) lasso_lib_idp_list_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibIDPList",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_lib_idp_list_new:
 * 
 * Creates a new <lib:IDPList/> node object.
 *
 * In the request envelope, some profiles may wish to allow the service
 * provider to transport a list of identity providers to the user agent. This
 * specification provides a schema that profiles SHOULD use for this purpose.
 * 
 * Return value: the new @LassoLibIDPList
 **/
LassoNode* lasso_lib_idp_list_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_IDP_LIST, NULL));
}
