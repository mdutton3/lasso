/* $Id: is_inquiry.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "../private.h"
#include "is_inquiry.h"
#include "idwsf2_strings.h"

/**
 * SECTION:is_inquiry
 * @short_description: &lt;is:Inquiry&gt;
 *
 * <figure><title>Schema fragment for is:Inquiry</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="InquiryType">
 *   <xs:sequence>
 *     <xs:element ref="Help" minOccurs="0"/>
 *     <xs:choice maxOccurs="unbounded">
 *       <xs:element ref="Select" minOccurs="0" maxOccurs="unbounded"/>
 *       <xs:element name="Confirm" type="InquiryElementType"
 *         minOccurs="0" maxOccurs="unbounded"/>
 *         <xs:element ref="Text" minOccurs="0" maxOccurs="unbounded"/>
 *       </xs:choice>
 *     </xs:sequence>
 *     <xs:attribute name="id" type="xs:ID" use="optional"/>
 *     <xs:attribute name="title" type="xs:string" use="optional"/>
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Help", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiry, Help), NULL, NULL, NULL},
	{ "Select", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiry, Select), NULL, NULL, NULL},
	{ "Confirm", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiry, Confirm), NULL, NULL, NULL},
	{ "Text", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiry, Text), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiry, id), NULL, NULL, NULL},
	{ "title", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2IsInquiry, title), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2IsInquiryClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Inquiry");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_IS_HREF, LASSO_IDWSF2_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_is_inquiry_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2IsInquiryClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2IsInquiry),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2IsInquiry", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_is_inquiry_new:
 *
 * Creates a new #LassoIdWsf2IsInquiry object.
 *
 * Return value: a newly created #LassoIdWsf2IsInquiry object
 **/
LassoIdWsf2IsInquiry*
lasso_idwsf2_is_inquiry_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_IS_INQUIRY, NULL);
}
