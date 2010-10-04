/* $Id: ps_object.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "ps_object.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:ps_object
 * @short_description: &lt;ps:Object&gt;
 *
 * <figure><title>Schema fragment for ps:Object</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="ObjectType">
 *   <xs:sequence>
 *     <xs:element ref="ObjectID" minOccurs="0"/>
 *     <xs:element name="DisplayName" type="LocalizedDisplayNameType" minOccurs="1"
 *             maxOccurs="unbounded"/>
 *     <xs:element name="Tag" type="TagType" minOccurs="0"/>
 *     <xs:element ref="Object" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element name="ObjectRef" type="ObjectIDType" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="NodeType" type="xs:anyURI" use="required"/>
 *   <xs:attribute name="CreatedDateTime" type="xs:dateTime" use="optional"/>
 *   <xs:attribute name="ModifiedDateTime" type="xs:dateTime" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "ObjectID", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, ObjectID), NULL, NULL, NULL},
	{ "DisplayName", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, DisplayName), NULL, NULL, NULL},
	{ "Tag", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, Tag), NULL, NULL, NULL},
	{ "Object", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, Object), NULL, NULL, NULL},
	{ "ObjectRef", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, ObjectRef), NULL, NULL, NULL},
	{ "NodeType", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, NodeType), NULL, NULL, NULL},
	{ "CreatedDateTime", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, CreatedDateTime), NULL, NULL, NULL},
	{ "ModifiedDateTime", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2PsObject, ModifiedDateTime), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2PsObjectClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Object");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_PS_HREF, LASSO_IDWSF2_PS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_ps_object_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2PsObjectClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2PsObject),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2PsObject", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_ps_object_new:
 *
 * Creates a new #LassoIdWsf2PsObject object.
 *
 * Return value: a newly created #LassoIdWsf2PsObject object
 **/
LassoIdWsf2PsObject*
lasso_idwsf2_ps_object_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_PS_OBJECT, NULL);
}
