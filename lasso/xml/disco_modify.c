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

#include <lasso/xml/disco_modify.h>

/*
 * Schema fragment (liberty-idwsf-disco-svc-1.0-errata-v1.0.xsd):
 * 
 * <xs:element name="Modify" type="ModifyType"/>
 * <xs:complexType name="ModifyType">
 *   <xs:sequence>
 *     <xs:group ref="ResourceIDGroup"/>
 *     <xs:element name="InsertEntry" type="InsertEntryType" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="RemoveEntry" type="RemoveEntryType" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 * 
 * <xs:group name="ResourceIDGroup">
 *   <xs:sequence>
 *     <xs:choice minOccurs="0" maxOccurs="1">
 *       <xs:element ref="ResourceID"/>
 *       <xs:element ref="EncryptedResourceID"/>
 *     </xs:choice>
 *   </xs:sequence>
 * </xs:group>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoDiscoModify *modify = LASSO_DISCO_MODIFY(node); \
	struct XmlSnippet snippets[] = { \
		{ "ResourceID", SNIPPET_CONTENT, (void**)&(modify->ResourceID) },	\
		{ "EncryptedResourceID", SNIPPET_CONTENT, (void**)&(modify->EncryptedResourceID) }, \
		{ "InsertEntry", SNIPPET_LIST_NODES, (void**)&(modify->InsertEntry) }, \
		{ "RemoveEntry", SNIPPET_LIST_NODES, (void**)&(modify->RemoveEntry) }, \
		{ "id", SNIPPET_ATTRIBUTE, (void**)&(modify->id) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "Modify");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX));
	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode)) {
		return -1;
	}

	init_xml_with_snippets(xmlnode, snippets);

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoModify *node)
{
	node->ResourceID = NULL;
	node->EncryptedResourceID = NULL;
	node->InsertEntry = NULL;
	node->RemoveEntry = NULL;
	node->id = NULL;
}

static void
class_init(LassoDiscoModifyClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->get_xmlNode = get_xmlNode;
	nodeClass->init_from_xml = init_from_xml;
}

GType
lasso_disco_modify_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoModifyClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoModify),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
						   "LassoDiscoModify", &this_info, 0);
	}
	return this_type;
}

LassoDiscoModify*
lasso_disco_modify_new(char     *resourceID,
		       gboolean  encrypted)
{
	LassoDiscoModify *modify;

	g_return_val_if_fail (resourceID != NULL, NULL);

	modify = g_object_new(LASSO_TYPE_DISCO_MODIFY, NULL);

	/* ResourceID or EncryptedResourceID */
	if (encrypted == FALSE) {
		modify->ResourceID = g_strdup(resourceID);
	}
	else {
		modify->EncryptedResourceID = g_strdup(resourceID);
	}

	return modify;
}
