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
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibScoping *scoping = LASSO_LIB_SCOPING(node);
	char s[20];

	xmlnode = xmlNewNode(NULL, "Scoping");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (scoping->ProxyCount) {
		snprintf(s, 19, "%d", scoping->ProxyCount);
		xmlNewTextChild(xmlnode, NULL, "ProxyCount", s);
	}
	if (scoping->IDPList)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(scoping->IDPList)));

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibScoping *scoping = LASSO_LIB_SCOPING(node);
	char *proxy_count = NULL;
	struct XmlSnippet snippets[] = {
		{ "ProxyCount", 'c', (void**)&proxy_count },
		{ "IDPList", 'n', (void**)&(scoping->IDPList) },
		{ NULL, 0, NULL}
	};

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	if (proxy_count) {
		scoping->ProxyCount = atoi(proxy_count);
		xmlFree(proxy_count);
	}

	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibScoping *node)
{
	node->ProxyCount = 0;
	node->IDPList = NULL;
}

static void
class_init(LassoLibScopingClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_scoping_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibScopingClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibScoping),
			0,
			(GInstanceInitFunc) instance_init,
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
LassoLibScoping*
lasso_lib_scoping_new()
{
	return g_object_new(LASSO_TYPE_LIB_SCOPING, NULL);
}

