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
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibIDPEntry *entry = LASSO_LIB_IDP_ENTRY(node);

	xmlnode = xmlNewNode(NULL, "IDPEntry");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (entry->ProviderID)
		xmlNewTextChild(xmlnode, NULL, "ProviderID", entry->ProviderID);
	if (entry->ProviderName)
		xmlNewTextChild(xmlnode, NULL, "ProviderName", entry->ProviderName);
	if (entry->Loc)
		xmlNewTextChild(xmlnode, NULL, "Loc", entry->Loc);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibIDPEntry *entry = LASSO_LIB_IDP_ENTRY(node);
	xmlNode *t;

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		if (t->type == XML_ELEMENT_NODE && strcmp(t->name, "Loc") == 0) {
			entry->Loc = xmlNodeGetContent(t);
		}
		if (t->type == XML_ELEMENT_NODE && strcmp(t->name, "ProviderID") == 0) {
			entry->ProviderID = xmlNodeGetContent(t);
		}
		if (t->type == XML_ELEMENT_NODE && strcmp(t->name, "ProviderName") == 0) {
			entry->ProviderName = xmlNodeGetContent(t);
		}
		t = t->next;
	}
	return 0;
}
	
/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibIDPEntry *node)
{
	node->ProviderID = NULL;
	node->ProviderName = NULL;
	node->Loc = NULL;
}

static void
class_init(LassoLibIDPEntryClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_idp_entry_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibIDPEntryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibIDPEntry),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibIDPEntry", &this_info, 0);
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
LassoNode*
lasso_lib_idp_entry_new()
{
	return g_object_new(LASSO_TYPE_LIB_IDP_ENTRY, NULL);
}

