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

#include <lasso/xml/saml_subject_statement_abstract.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<complexType name="SubjectStatementAbstractType" abstract="true">
  <complexContent>
    <extension base="saml:StatementAbstractType">
      <sequence>
        <element ref="saml:Subject"/>
      </sequence>
    </extension>
  </complexContent>
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
	LassoSamlSubjectStatementAbstract *statement;
	
	statement = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "SubjectStatementAbstract");
	if (statement->Subject)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(statement->Subject)));

	return xmlnode;
}

static void
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	xmlNode *t;
	LassoSamlSubjectStatementAbstract *statement;
	
	statement = LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(node);

	parent_class->init_from_xml(node, xmlnode);
	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		
		if (strcmp(t->name, "Subject") == 0)
			statement->Subject = LASSO_SAML_SUBJECT(
					lasso_node_new_from_xmlNode(t));
		t = t->next;
	}
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlSubjectStatementAbstract *node)
{
	node->Subject = NULL;
}

static void
class_init(LassoSamlSubjectStatementAbstractClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_subject_statement_abstract_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlSubjectStatementAbstractClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlSubjectStatementAbstract),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_STATEMENT_ABSTRACT,
				"LassoSamlSubjectStatementAbstract", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_subject_statement_abstract_new:
 * 
 * Creates a new <saml:SubjectStatementAbstract> node object.
 * 
 * Return value: the new @LassoSamlSubjectStatementAbstract
 **/
LassoNode*
lasso_saml_subject_statement_abstract_new()
{
	return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT, NULL));
}

