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

#include <lasso/xml/disco_credentials.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-v1.0.xsd):
 * 
 * <xs:element name="Credentials" minOccurs="0">
 *   <xs:complexType>
 *     <xs:sequence>
 *       <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *     </xs:sequence>
 *   </xs:complexType>
 * </xs:element>
 */


/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

#define snippets() \
	LassoDiscoCredentials *credentials = LASSO_DISCO_CREDENTIALS(node); \
	struct XmlSnippetObsolete snippets[] = { \
		{ "", SNIPPET_LIST_NODES, (void**)&credentials->any }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	GList *option;
	xmlNode *xmlnode, *options_xmlNode;
	snippets();

	xmlnode = xmlNewNode(NULL, "Credentials");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));

	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	xmlNode *option_xmlNode;
	snippets();
	
	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	init_xml_with_snippets(xmlnode, snippets);

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoCredentials *node)
{
	node->any = NULL;
}

static void
class_init(LassoDiscoCredentialsClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_disco_credentials_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoCredentialsClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoCredentials),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoCredentials", &this_info, 0);
	}
	return this_type;
}

LassoDiscoCredentials*
lasso_disco_credentials_new()
{
	LassoDiscoCredentials *node;

	node = g_object_new(LASSO_TYPE_DISCO_CREDENTIALS, NULL);

	return node;
}
