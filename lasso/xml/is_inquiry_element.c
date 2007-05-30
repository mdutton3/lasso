/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: See AUTHORS file in top-level directory.
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

#include <lasso/xml/is_inquiry_element.h>

/*
 * Schema fragments (liberty-idwsf-interaction-svc-v1.0.xsd):
 *
 * <xs:complexType name="InquiryElementType" abstract="true">
 *   <xs:sequence>
 *     <xs:element ref="Help" minOccurs="0"/>
 *     <xs:element ref="Hint" minOccurs="0"/>
 *     <xs:element name="Label" type="xs:normalizedString" minOccurs="0"/>
 *     <xs:element name="Value" type="xs:normalizedString" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="name" type="xs:ID" use="required"/>
 * </xs:complexType>
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Help", SNIPPET_NODE, G_STRUCT_OFFSET(LassoIsInquiryElement, Help) },
	{ "Hint", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoIsInquiryElement, Hint) },
	{ "Label", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoIsInquiryElement, Label) },
	{ "Value", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoIsInquiryElement, Value) },
	{ "name", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsInquiryElement, name) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIsInquiryElement *node)
{
	node->Help = NULL;
	node->Hint = NULL;
	node->Label = NULL;
	node->Value = NULL;
	node->name = NULL;
}

static void
class_init(LassoIsInquiryElementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "InquiryElement");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_inquiry_element_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsInquiryElementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsInquiryElement),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsInquiryElement", &this_info, 0);
	}
	return this_type;
}

LassoIsInquiryElement*
lasso_is_inquiry_element_new(const char *name)
{
	LassoIsInquiryElement *node;

	node = g_object_new(LASSO_TYPE_IS_INQUIRY_ELEMENT, NULL);

	node->name = g_strdup(name);

	return node;
}
