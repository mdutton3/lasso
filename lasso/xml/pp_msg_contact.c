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

#include <lasso/xml/pp_msg_contact.h>
#include <lasso/id-wsf/personal_profile_service.h>

/*
 * Schema fragment (liberty-idwsf-dst-v1.0.xsd):
 *
 * <xs:element name="MsgContact" type="MsgContactType"/>
 * <xs:complexType name="MsgContactType">
 *   <xs:sequence>
 *     <xs:element ref="Nick" minOccurs="0"/>
 *     <xs:element ref="LNick" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element ref="LComment" minOccurs="0"/>
 *     <xs:element ref="MsgType" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element ref="MsgMethod" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element ref="MsgTechnology" minOccurs="0" maxOccurs="unbounded"/>
 *     <xs:element ref="MsgProvider" minOccurs="0"/>
 *     <xs:element ref="MsgAccount" minOccurs="0"/>
 *     <xs:element ref="MsgSubaccount" minOccurs="0"/>
 *     <xs:element ref="Extension" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attributeGroup ref="commonAttributes"/>
 * </xs:complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "MsgProvider", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoPPMsgContact, MsgProvider) },
	{ "MsgAccount", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoPPMsgContact, MsgAccount) },
	{NULL, 0, 0}
};

static LassoNodeClass *parent_class = NULL;

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoPPMsgContact *node)
{
	node->MsgProvider = NULL;
	node->MsgAccount = NULL;
}

static void
class_init(LassoPPMsgContactClass *klass)
{
	LassoNodeClass *nodeClass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nodeClass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nodeClass, "MsgContact");
	lasso_node_class_set_ns(nodeClass, LASSO_PP_HREF, LASSO_PP_PREFIX);
	lasso_node_class_add_snippets(nodeClass, schema_snippets);
}

GType
lasso_pp_msg_contact_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoPPMsgContactClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoPPMsgContact),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoPPMsgContact", &this_info, 0);
	}
	return this_type;
}

LassoPPMsgContact*
lasso_pp_msg_contact_new()
{
	LassoPPMsgContact *msgContact;

	msgContact = g_object_new(LASSO_TYPE_PP_MSG_CONTACT, NULL);

	return msgContact;
}

