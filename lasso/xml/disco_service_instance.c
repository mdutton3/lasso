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

#include <lasso/xml/disco_service_instance.h>

/*
Schema fragment (liberty-idwsf-disco-svc-v1.0.xsd):

<xs:complexType name="ServiceInstanceType">
   <xs:sequence>
      <xs:element ref="ServiceType"/>
      <xs:element name="ProviderID" type="md:entityIDType"/>
      <xs:element name="Description" type="DescriptionType" minOccurs="1" maxOccurs="unbounded"/>
   </xs:sequence>
</xs:complexType>

<xs:element name="ServiceType" type="xs:anyURI"/>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDiscoServiceInstance *instance = \
		LASSO_DISCO_SERVICE_INSTANCE(node); \
	struct XmlSnippet snippets[] = { \
		{ "ServiceType", 'c', (void**)&(instance->ServiceType) }, \
		{ "ProviderID",  'c', (void**)&(instance->ProviderID) }, \
		{ "Description", 's', (void**)&(instance->Description) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "ServiceInstance");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));
	lasso_node_build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoServiceInstance *node)
{
	node->ServiceType = NULL;
	node->ProviderID = NULL;
	node->Description = NULL;
}

static void
class_init(LassoDiscoServiceInstanceClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_disco_service_instance_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoServiceInstanceClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoServiceInstance),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoServiceInstance", &this_info, 0);
	}
	return this_type;
}

LassoDiscoServiceInstance*
lasso_disco_service_instance_new()
{
	return g_object_new(LASSO_TYPE_DISCO_SERVICE_INSTANCE, NULL);
}
