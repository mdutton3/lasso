/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
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

#include <lasso/xml/disco_resource_offering.h>

/*
Schema fragment (liberty-idwsf-disco-svc-v1.0.xsd):

<xs:element name="ResourceOffering" type="ResourceOfferingType"/>
<xs:complexType name="ResourceOfferingType">
   <xs:sequence>
      <xs:group ref="ResourceIDGroup"/>
      <xs:element name="ServiceInstance" type="ServiceInstanceType"/>
      <xs:element ref="Options" minOccurs="0"/>
      <xs:element name="Abstract" type="xs:string" minOccurs="0"/>
   </xs:sequence>
   <xs:attribute name="entryID" type="IDType" use="optional"/>
</xs:complexType>

<xs:group name="ResourceIDGroup">
   <xs:sequence>
      <xs:choice minOccurs="0" maxOccurs="1">
         <xs:element ref="ResourceID"/>
         <xs:element ref="EncryptedResourceID"/>
      </xs:choice>
   </xs:sequence>
</xs:group>

Schema fragment (liberty-idwsf-utility-1.0-errata-v1.0.xsd)

<xs:simpleType name="IDType">
   <xs:restriction base="xs:string"/>
</xs:simpleType>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDiscoResourceOffering *resource = \
		LASSO_DISCO_RESOURCE_OFFERING(node); \
	struct XmlSnippet snippets[] = { \
		{ "ResourceID", SNIPPET_CONTENT, (void**)&(resource->ResourceID) },	\
		{ "EncryptedResourceID", SNIPPET_CONTENT, (void**)&(resource->EncryptedResourceID) }, \
		{ "ServiceInstance", SNIPPET_NODE, (void**)&(resource->ServiceInstance) }, \
		{ "Options", SNIPPET_NODE, (void**)&(resource->Options) }, \
		{ "Abstract", SNIPPET_CONTENT, (void**)&(resource->Abstract) }, \
		{ "entryID", SNIPPET_ATTRIBUTE, (void**)&(resource->entryID) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "ResourceOffering");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));
	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode)) {
		return -1;
	}

	init_xml_with_snippets(xmlnode, snippets);
	
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoResourceOffering *node)
{
	node->ResourceID = NULL;
	node->EncryptedResourceID = NULL;
	node->ServiceInstance = NULL;
	node->Options = NULL;
	node->Abstract = NULL;
	node->entryID = NULL;
}

static void
class_init(LassoDiscoResourceOfferingClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_disco_resource_offering_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoResourceOfferingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoResourceOffering),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoResourceOffering", &this_info, 0);
	}
	return this_type;
}

LassoDiscoResourceOffering*
lasso_disco_resource_offering_new()
{
	return g_object_new(LASSO_TYPE_DISCO_RESOURCE_OFFERING, NULL);
}
