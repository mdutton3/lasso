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

#include <lasso/xml/lib_authn_context.h>

/*
The Schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:element name="AuthnContext">
  <xs:complexType>
    <xs:sequence>
      <xs:element name="AuthnContextClassRef" type="xs:anyURI" minOccurs="0"/>
      <xs:choice>
        <xs:element ref="ac:AuthenticationContextStatement"/>
        <xs:element name="AuthnContextStatementRef" type="xs:anyURI"/>
      </xs:choice>
    </xs:sequence>
  </xs:complexType>
</xs:element>

From schema liberty-authentication-context-v1.2.xsd:
<xs:element name="AuthenticationContextStatement" type="AuthenticationContextStatementType">
  <xs:annotation>
    <xs:documentation>
      A particular assertion on an identity
      provider's part with respect to the authentication
      context associated with an authentication assertion. 
    </xs:documentation>
  </xs:annotation>
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

	xmlnode = parent_class->get_xmlNode(node);
	if (LASSO_LIB_AUTHN_CONTEXT(node)->AuthnContextClassRef)
		xmlNewTextChild(xmlnode, NULL, "AuthnContextClassRef",
				LASSO_LIB_AUTHN_CONTEXT(node)->AuthnContextClassRef);
	if (LASSO_LIB_AUTHN_CONTEXT(node)->AuthnContextStatementRef)
		xmlNewTextChild(xmlnode, NULL, "AuthnContextStatementRef",
				LASSO_LIB_AUTHN_CONTEXT(node)->AuthnContextStatementRef);

	xmlNodeSetName(xmlnode, "AuthnContext");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibAuthnContext *context = LASSO_LIB_AUTHN_CONTEXT(node);
	xmlNode *t;

        parent_class->init_from_xml(node, xmlnode);

	t = xmlnode->children;
	while (t) {
		if (t->type == XML_ELEMENT_NODE) {
			if (strcmp(t->name, "AuthnContextClassRef") == 0)
				context->AuthnContextClassRef = xmlNodeGetContent(t);
			if (strcmp(t->name, "AuthnContextStatementRef") == 0 )
				context->AuthnContextStatementRef = xmlNodeGetContent(t);
		}
		t = t->next;
	}

}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAuthnContext *node)
{
	node->AuthnContextClassRef = NULL;
	node->AuthnContextStatementRef = NULL;
}

static void
class_init(LassoLibAuthnContextClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_authn_context_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAuthnContextClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAuthnContext),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoLibAuthnContext", &this_info, 0);
	}
	return this_type;
}

LassoNode*
lasso_lib_authn_context_new() {
	return g_object_new(LASSO_TYPE_LIB_AUTHN_CONTEXT, NULL);
}

