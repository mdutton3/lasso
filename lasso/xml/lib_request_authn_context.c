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

#include <lasso/xml/lib_request_authn_context.h>

/*
Information describing which authentication context the requester desires the
identity provider to use in authenticating the Principal.

Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="RequestAuthnContext">
  <xs:complexType>
    <xs:sequence>
      <xs:choice>
        <xs:element name="AuthnContextClassRef" type="xs:anyURI" maxOccurs="unbounded"/>
        <xs:element name="AuthnContextStatementRef" type="xs:anyURI" maxOccurs="unbounded"/>
      </xs:choice>
      <xs:element name="AuthnContextComparison" type="AuthnContextComparisonType" minOccurs="0"/>
    </xs:sequence>
  </xs:complexType>
</xs:element>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoLibRequestAuthnContext *context = LASSO_LIB_REQUEST_AUTHN_CONTEXT(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "RequestAuthnContext");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (context->AuthnContextClassRef)
		xmlNewTextChild(xmlnode, NULL,
				"AuthnContextClassRef", context->AuthnContextClassRef);
	if (context->AuthnContextStatementRef)
		xmlNewTextChild(xmlnode, NULL,
				"AuthnContextStatementRef", context->AuthnContextStatementRef);
	if (context->AuthnContextComparisonType)
		xmlNewTextChild(xmlnode, NULL,
				"AuthnContextComparisonType", context->AuthnContextComparisonType);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibRequestAuthnContext *context = LASSO_LIB_REQUEST_AUTHN_CONTEXT(node);
	xmlNode *t, *n;

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		n = t;
		t = t->next;
		if (n->type != XML_ELEMENT_NODE)
			continue;
		if (strcmp(n->name, "AuthnContextClassRef") == 0) {
			context->AuthnContextClassRef = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "AuthnContextStatementRef") == 0) {
			context->AuthnContextStatementRef = xmlNodeGetContent(n);
			continue;
		}
		if (strcmp(n->name, "AuthnContextComparisonType") == 0) {
			context->AuthnContextComparisonType = xmlNodeGetContent(n);
			continue;
		}
	}
	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibRequestAuthnContext *node)
{
	node->AuthnContextClassRef = NULL;
	node->AuthnContextStatementRef = NULL;
	node->AuthnContextComparisonType = NULL;
}

static void
class_init(LassoLibRequestAuthnContextClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_request_authn_context_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibRequestAuthnContextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibRequestAuthnContext),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibRequestAuthnContext", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_request_authn_context_new()
{
	return g_object_new(LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT, NULL);
}
