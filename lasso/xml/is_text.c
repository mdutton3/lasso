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

#include <lasso/xml/is_text.h>

/*
 * Schema fragments (liberty-idwsf-interaction-svc-v1.0.xsd):
 *
 * <xs:element name="Text" type="TextType"/>
 * <xs:complexType name="TextType">
 *   <xs:complexContent>
 *     <xs:extension base="InquiryElementType">
 *       <xs:attribute name="minChars" type="xs:integer" use="optional"/>
 *       <xs:attribute name="maxChars" type="xs:integer" use="optional"/>
 *       <xs:attribute name="format" type="xs:string" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 *
 */ 

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "minChars", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsText, minChars) },
	{ "maxChars", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsText, maxChars) },
	{ "format", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsText, format) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIsText *node)
{
	node->minChars = 0;
	node->maxChars = 0;
	node->format = NULL;
}

static void
class_init(LassoIsTextClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Text");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_text_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsTextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsText),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsText", &this_info, 0);
	}
	return this_type;
}

LassoIsText*
lasso_is_text_new()
{
	LassoIsText *node;

	node = g_object_new(LASSO_TYPE_IS_TEXT, NULL);

	return node;
}
