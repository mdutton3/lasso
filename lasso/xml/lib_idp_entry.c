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

#include <lasso/xml/lib_idp_entry.h>

/*
Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="IDPEntry">
  <xs:complexType>
    <xs:sequence>
      <xs:element ref="ProviderID"/>
      <xs:element name="ProviderName" type="xs:string" minOccurs="0"/>
      <xs:element name="Loc" type="xs:anyURI"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_lib_idp_entry_set_providerID:
 * @node: the pointer to <lib:IDPEntry/> node object
 * @providerID: the value of "ProviderID" element
 * 
 * Sets the "ProviderID" element [required].
 *
 * It's the identity provider's unique identifier.
 **/
void
lasso_lib_idp_entry_set_providerID(LassoLibIDPEntry *node,
				   const xmlChar *providerID)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_IDP_ENTRY(node));
  g_assert(providerID != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderID", providerID, FALSE);
}

/**
 * lasso_lib_idp_entry_set_providerName:
 * @node: the pointer to <lib:IDPEntry/> node object
 * @providerName: the value of "ProviderName" element
 * 
 * Sets the "ProviderName" element [optional].
 *
 * It's the identity provider's human-readable name.
 **/
void
lasso_lib_idp_entry_set_providerName(LassoLibIDPEntry *node,
				     const xmlChar *providerName)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_IDP_ENTRY(node));
  g_assert(providerName != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "ProviderName", providerName, FALSE);
}

/**
 * lasso_lib_idp_entry_set_loc:
 * @node: the pointer to <lib:IDPEntry/> node object
 * @loc: the value of "Loc" element
 * 
 * Sets the "Loc" element [optional].
 *
 * It's the identity provider's URI, to which authentication requests may be
 * sent. If present, this MUST be set to the value of the identity provider's
 * <SingleSignOnService> element, obtained from their metadata
 * ([LibertyMetadata]).
 **/
void
lasso_lib_idp_entry_set_loc(LassoLibIDPEntry *node,
			    const xmlChar *loc)
{
  LassoNodeClass *class;
  g_assert(LASSO_IS_LIB_IDP_ENTRY(node));
  g_assert(loc != NULL);

  class = LASSO_NODE_GET_CLASS(node);
  class->new_child(LASSO_NODE (node), "Loc", loc, FALSE);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_lib_idp_entry_instance_init(LassoLibIDPEntry *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoLibHRef, lassoLibPrefix);
  class->set_name(LASSO_NODE(node), "IDPEntry");
}

static void
lasso_lib_idp_entry_class_init(LassoLibIDPEntryClass *klass)
{
}

GType lasso_lib_idp_entry_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoLibIDPEntryClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_lib_idp_entry_class_init,
      NULL,
      NULL,
      sizeof(LassoLibIDPEntry),
      0,
      (GInstanceInitFunc) lasso_lib_idp_entry_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoLibIDPEntry",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_lib_idp_entry_new:
 *
 * Creates a new <lib:IDPEntry/> node object.
 * 
 * Return value: the new @LassoLibIDPEntry
 **/
LassoNode* lasso_lib_idp_entry_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_LIB_IDP_ENTRY, NULL));
}
