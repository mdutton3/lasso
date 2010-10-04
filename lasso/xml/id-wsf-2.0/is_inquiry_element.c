/* $Id: is_inquiry_element.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "is_inquiry_element.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:is_inquiry_element
 * @short_description: &lt;is:InquiryElement&gt;
 *
 * <figure><title>Schema fragment for is:InquiryElement</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Help", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiryElement, Help), NULL, NULL, NULL},
	{ "Hint", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiryElement, Hint), NULL, NULL, NULL},
	{ "Label", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiryElement, Label), NULL, NULL, NULL},
	{ "Value", SNIPPET_CONTENT,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiryElement, Value), NULL, NULL, NULL},
	{ "name", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiryElement, name), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2IsInquiryElementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Confirm");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_IS_HREF, LASSO_IDWSF2_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_is_inquiry_element_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2IsInquiryElementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2IsInquiryElement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2IsInquiryElement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_is_inquiry_element_new:
 *
 * Creates a new #LassoIdWsf2IsInquiryElement object.
 *
 * Return value: a newly created #LassoIdWsf2IsInquiryElement object
 **/
LassoIdWsf2IsInquiryElement*
lasso_idwsf2_is_inquiry_element_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_IS_INQUIRY_ELEMENT, NULL);
}
