/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
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

#include <lasso/xml/saml_attribute_statement.h>

/*
 * The schema fragment (oasis-sstc-saml-schema-assertion-1.1.xsd):
 * 
 * <element name="AttributeStatement" type="saml:AttributeStatementType"/>
 * <complexType name="AttributeStatementType">
 *   <complexContent>
 *     <extension base="saml:SubjectStatementAbstractType">
 *       <sequence>
 *         <element ref="saml:Attribute" maxOccurs="unbounded"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoSamlAttributeStatement *statement = \
		LASSO_SAML_ATTRIBUTE_STATEMENT(node); \
	struct XmlSnippet snippets[] = { \
		{ "Attribute", SNIPPET_LIST_NODES, (void**)&(statement->Attribute) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "AttributeStatement");
	build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlAttributeStatement *node)
{
	node->Attribute = NULL;
}

static void
class_init(LassoSamlAttributeStatementClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
}

GType
lasso_saml_attribute_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAttributeStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAttributeStatement),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
						   "LassoSamlAttributeStatement",
						   &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_attribute_statement_new:
 * 
 * Creates a new <saml:AttributeStatement> node object.
 * 
 * Return value: the new @LassoSamlAttributeStatement
 **/
LassoNode*
lasso_saml_attribute_statement_new()
{
	return g_object_new(LASSO_TYPE_SAML_ATTRIBUTE_STATEMENT, NULL);
}

