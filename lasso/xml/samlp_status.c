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

#include <lasso/xml/samlp_status.h>

/*
Schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<element name="Status" type="samlp:StatusType"/>
<complexType name="StatusType">
  <sequence>
    <element ref="samlp:StatusCode"/>
    <element ref="samlp:StatusMessage" minOccurs="0" maxOccurs="1"/>
    <element ref="samlp:StatusDetail" minOccurs="0"/>
  </sequence>
</complexType>

<element name="StatusMessage" type="string"/>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{ 
	xmlNode *xmlnode;
	LassoSamlpStatus *status = LASSO_SAMLP_STATUS(node);

	xmlnode = xmlNewNode(NULL, "Status");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX));
	if (status->StatusCode)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(status->StatusCode)));

	if (status->StatusMessage)
		xmlNewTextChild(xmlnode, NULL, "StatusMessage", status->StatusMessage);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	xmlNode *t;
	LassoSamlpStatus *status = LASSO_SAMLP_STATUS(node);

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "StatusCode") == 0) {
			status->StatusCode = LASSO_SAMLP_STATUS_CODE(lasso_node_new_from_xmlNode(t));
		}
		if (strcmp(t->name, "StatusMessage") == 0) {
			status->StatusMessage = xmlNodeGetContent(t);
		}
		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
instance_init(LassoSamlpStatus *node)
{
	node->StatusCode = NULL;
	node->StatusMessage = NULL;
}

static void
class_init(LassoSamlpStatusClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType lasso_samlp_status_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpStatusClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpStatus),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlpStatus", &this_info, 0);
	}
	return this_type;
}

LassoSamlpStatus*
lasso_samlp_status_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_STATUS, NULL);
}

