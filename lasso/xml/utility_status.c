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

#include <lasso/xml/utility_status.h>

/*
 * Schema fragment
 *
 * <xs:element name="Status" type="StatusType">
 *   <xs:annotation>
 *     <xs:documentation> A standard Status type</xs:documentation>
 *   </xs:annotation>
 * </xs:element>
 * <xs:complexType name="StatusType">
 *   <xs:annotation>
 *     <xs:documentation> A type that may be used for status codes. </xs:documentation>
 *   </xs:annotation>
 *   <xs:sequence>
 *     <xs:element ref="Status" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="code" type="xs:QName" use="required"/>
 *   <xs:attribute name="ref" type="xs:NCName" use="optional"/>
 *   <xs:attribute name="comment" type="xs:string" use="optional"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoUtilityStatus *status = LASSO_UTILITY_STATUS(node); \
	struct XmlSnippet snippets[] = { \
		{ "Status", SNIPPET_NODE, (void**)&(status->Status) }, \
		{ "code", SNIPPET_ATTRIBUTE, (void**)&(status->code) }, \
		{ "ref", SNIPPET_ATTRIBUTE, (void**)&(status->ref) }, \
		{ "comment", SNIPPET_ATTRIBUTE, (void**)&(status->comment) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "Status");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));

	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
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
instance_init(LassoUtilityStatus *node)
{
	node->code = NULL;
	node->ref = NULL;
	node->comment = NULL;
}

static void
class_init(LassoUtilityStatusClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_utility_status_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoUtilityStatusClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoUtilityStatus),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoUtilityStatus", &this_info, 0);
	}
	return this_type;
}

LassoUtilityStatus*
lasso_utility_status_new(const char *code)
{
	LassoUtilityStatus *status;
	status = g_object_new(LASSO_TYPE_UTILITY_STATUS, NULL);

	status->code = g_strdup(code);

	return status;
}

