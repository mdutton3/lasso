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

#include <lasso/xml/lib_idp_entries.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="IDPEntries">
  <xs:complexType>
    <xs:sequence>
      <xs:element ref="IDPEntry" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_lib_idp_entries_add_idpEntry:
 * @node: the pointer to <lib:IDPEntries/> node object
 * @idpEntry: the pointer to <lib:IDPEntry/> node object
 * 
 * Adds an "IDPEntry" element [required].
 *
 * It describes an identity provider that the service provider supports.
 **/
void
lasso_lib_idp_entries_add_idpEntry(LassoLibIDPEntries *node,
				   LassoLibIDPEntry *idpEntry)
{
  g_assert(LASSO_IS_LIB_IDP_ENTRIES(node));
  g_assert(LASSO_IS_LIB_IDP_ENTRY(idpEntry));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(idpEntry), TRUE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_idp_entries_instance_init(LassoLibIDPEntries *instance)
{
  LassoNode *node = LASSO_NODE(instance);
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);

  class->new_ns(node, "urn:liberty:iff:2003-08", "lib");
  class->set_name(node, "IDPEntries");
}

static void
lasso_lib_idp_entries_class_init(LassoLibIDPEntriesClass *klass)
{
}

GType lasso_lib_idp_entries_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibIDPEntriesClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_idp_entries_class_init,
      NULL,
      NULL,
      sizeof(LassoLibIDPEntries),
      0,
      (GInstanceInitFunc) lasso_lib_idp_entries_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibIDPEntries",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_lib_idp_entries_new:
 * 
 * Creates a new "<lib:IDPEntries/>" node object.
 * 
 * Return value: the new @LassoLibIDPEntries
 **/
LassoNode* lasso_lib_idp_entries_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_IDP_ENTRIES, NULL));
}
