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

#include <lasso/xml/is_inquiry.h>

/*
 * Schema fragments (liberty-idwsf-interaction-svc-v1.0.xsd):
 *
 * <xs:element name="Inquiry" type="InquiryType"/>
 * <xs:complexType name="InquiryType">
 *    <xs:sequence>
 *      <xs:element ref="Help" minOccurs="0"/>
 *      <xs:choice maxOccurs="unbounded">
 *        <xs:element ref="Select" minOccurs="0" maxOccurs="unbounded"/>
 *        <xs:element name="Confirm" type="InquiryElementType" minOccurs="0" maxOccurs="unbounded"/>
 *        <xs:element ref="Text" minOccurs="0" maxOccurs="unbounded"/>
 *      </xs:choice>
 *    </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 *   <xs:attribute name="title" type="xs:string" use="optional"/>
 * </xs:complexType>
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Help", SNIPPET_NODE, G_STRUCT_OFFSET(LassoIsInquiry, Help) },
	{ "Select", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoIsInquiry, Select) },
	{ "Confirm", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoIsInquiry, Confirm) },
	{ "Text", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoIsInquiry, Text) },
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsInquiry, id) },
	{ "title", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsInquiry, title) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIsInquiry *node)
{
	node->Help = NULL;
	node->Select = NULL;
	node->Confirm = NULL;
	node->Text = NULL;
	node->id = NULL;
	node->title = NULL;
}

static void
class_init(LassoIsInquiryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Inquiry");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_inquiry_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsInquiryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsInquiry),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsInquiry", &this_info, 0);
	}
	return this_type;
}

LassoIsInquiry*
lasso_is_inquiry_new()
{
	LassoIsInquiry *node;

	node = g_object_new(LASSO_TYPE_IS_INQUIRY, NULL);

	return node;
}
