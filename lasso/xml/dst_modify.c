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

#include <lasso/xml/dst_modify.h>

/*
 * Schema fragment (liberty-idwsf-dst-v1.0.xsd):
 *
 * <xs:element name="Modify" type="ModifyType"/>
 * <xs:complexType name="ModifyType">
 *     <xs:sequence>
 *         <xs:group ref="ResourceIDGroup" minOccurs="0"/>
 *         <xs:element name="Modification" maxOccurs="unbounded">
 *             <xs:complexType>
 *                 <xs:sequence>
 *                     <xs:element name="Select" type="SelectType"/>
 *                     <xs:element name="NewData" minOccurs="0">
 *                         <xs:complexType>
 *                             <xs:sequence>
 *                                 <xs:any minOccurs="0" maxOccurs="unbounded"/>
 *                             </xs:sequence>
 *                         </xs:complexType>
 *                     </xs:element>
 *                 </xs:sequence>
 *                 <xs:attribute name="id" type="xs:ID"/>
 *                 <xs:attribute name="notChangedSince" type="xs:dateTime"/>
 *                 <xs:attribute name="overrideAllowed" type="xs:boolean" default="0"/>
 *             </xs:complexType>
 *         </xs:element>
 *         <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/>
 *     </xs:sequence>
 *     <xs:attribute name="id" type="xs:ID"/>
 *     <xs:attribute name="itemID" type="IDType"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModify, ResourceID) },
	{ "EncryptedResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModify,
							       EncryptedResourceID) },
	{ "Modification", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModify,
							Modification) },
	/* FIXME : implement Extension element */
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModify, id) },
	{ "itemID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModify, itemID) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	/* insure children are kept in same namespace */
	xmlNode *t;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		xmlSetNs(xmlnode, ns);
		insure_namespace(t, ns);
		t = t->next;
	}
}

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	xmlNs *ns;

	xmlnode = parent_class->get_xmlNode(node);
	ns = xmlNewNs(xmlnode, LASSO_DST_MODIFY(node)->hrefServiceType,
		      LASSO_DST_MODIFY(node)->prefixServiceType);
	xmlSetNs(xmlnode, ns);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDstModify *node)
{
	node->prefixServiceType = NULL;
	node->hrefServiceType = NULL;
}

static void
class_init(LassoDstModifyClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nodeClass, "Modify");
	lasso_node_class_add_snippets(nodeClass, schema_snippets);
}

GType
lasso_dst_modify_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDstModifyClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDstModify),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDstModify", &this_info, 0);
	}
	return this_type;
}

LassoDstModify*
lasso_dst_modify_new()
{
	LassoDstModify *modify;

	modify = g_object_new(LASSO_TYPE_DST_MODIFY, NULL);

	return modify;
}

