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

#include <lasso/xml/samlp_status_code.h>

/*
Schema fragment (oasis-sstc-saml-schema-protocol-1.0.xsd):

<element name="StatusCode" type="samlp:StatusCodeType"/>
<complexType name="StatusCodeType">
  <sequence>
    <element ref="samlp:StatusCode" minOccurs="0"/>
  </sequence>
  <attribute name="Value" type="QName" use="required"/>
</complexType>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoSamlpStatusCode *status_code = LASSO_SAMLP_STATUS_CODE(node);

	xmlnode = xmlNewNode(NULL, "StatusCode");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX));
	if (status_code->Value)
		xmlSetProp(xmlnode, "Value", status_code->Value);

	if (status_code->StatusCode)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(status_code->StatusCode)));

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoSamlpStatusCode *status_code = LASSO_SAMLP_STATUS_CODE(node);
	struct XmlSnippet snippets[] = {
		{ "StatusCode", 'n', (void**)&(status_code->StatusCode) },
		{ NULL, 0, NULL}
	};

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	status_code->Value = xmlGetProp(xmlnode, "Value");
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
instance_init(LassoSamlpStatusCode *node)
{
}

static void
class_init(LassoSamlpStatusCodeClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_samlp_status_code_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpStatusCodeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpStatusCode),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlpStatusCode",
				&this_info, 0);
	}
	return this_type;
}

LassoSamlpStatusCode*
lasso_samlp_status_code_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_STATUS_CODE, NULL);
}

