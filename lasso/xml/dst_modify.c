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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "private.h"
#include "dst_modify.h"
#include "idwsf_strings.h"

/**
 * SECTION:dst_modify
 * @short_description: &lt;dst:Modify&gt;
 *
 * <figure><title>Schema fragment for dst:Modify</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModify, ResourceID), NULL, NULL, NULL},
	{ "EncryptedResourceID", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDstModify,
			EncryptedResourceID), NULL, NULL, NULL },
	{ "Modification", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDstModify,
			Modification), NULL, NULL, NULL },
	{ "Extension", SNIPPET_EXTENSION, G_STRUCT_OFFSET(LassoDstModify, Extension), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModify, id), NULL, NULL, NULL},
	{ "itemID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDstModify, itemID), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	xmlNode *t = xmlnode->children;

	xmlSetNs(xmlnode, ns);
	while (t) {
		if (t->type == XML_ELEMENT_NODE && t->ns == NULL) {
			insure_namespace(t, ns);
		}
		t = t->next;
	}
}

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	xmlNs *ns;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_DST_MODIFY(node)->hrefServiceType,
			(xmlChar*)LASSO_DST_MODIFY(node)->prefixServiceType);
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoDstModify *modify = LASSO_DST_MODIFY(node);
	int rc = 0;

	rc = parent_class->init_from_xml(node, xmlnode);
	if (rc) {
		return rc;
	}

	modify->hrefServiceType = g_strdup((char*)xmlnode->ns->href);
	modify->prefixServiceType = lasso_get_prefix_for_dst_service_href(
			modify->hrefServiceType);
	if (modify->prefixServiceType == NULL) {
		/* XXX: what to do here ? */
	}

	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDstModifyClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->init_from_xml = init_from_xml;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Modify");
	lasso_node_class_add_snippets(nclass, schema_snippets);
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
			NULL,
			NULL
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

