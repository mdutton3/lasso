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
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "ResourceIDGroup", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDiscoModify, ResourceIDGroup) },
	{ "InsertEntry", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDiscoModify, InsertEntry) },
	{ "RemoveEntry", SNIPPET_LIST_NODES, G_STRUCT_OFFSET(LassoDiscoModify, RemoveEntry) },
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoDiscoModify, id) },
	{ NULL, 0, 0}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoDiscoModify *node)
{
	node->ResourceIDGroup = NULL;
	node->InsertEntry = NULL;
	node->RemoveEntry = NULL;
	node->id = NULL;
}

static void
class_init(LassoDiscoModifyClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Modify");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
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
lasso_disco_modify_new(LassoDiscoResourceIDGroup *resourceIDGroup)
{
	LassoDiscoModify *node;

	node = g_object_new(LASSO_TYPE_DISCO_MODIFY, NULL);

	/* FIXME : should ResourceIDGroup be a copy */
	node->ResourceIDGroup = resourceIDGroup;

	return node;
}

LassoDiscoModify*
lasso_disco_modify_new_from_message(const gchar *message)
{
	LassoDiscoModify *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_DISCO_MODIFY, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}
