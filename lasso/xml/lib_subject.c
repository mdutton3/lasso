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

#include <lasso/xml/lib_subject.h>

/*
The schema fragment (liberty-idff-protocols-schema-v1.2.xsd):

<xs:complexType name="SubjectType">
  <xs:complexContent>
    <xs:extension base="saml:SubjectType">
      <xs:sequence>
        <xs:element ref="IDPProvidedNameIdentifier"/>
      </xs:sequence>
    </xs:extension>
  </xs:complexContent>
</xs:complexType>
<xs:element name="Subject" type="SubjectType" substitutionGroup="saml:Subject"/>

*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode, *t;
	LassoLibSubject *subject = LASSO_LIB_SUBJECT(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	if (subject->IDPProvidedNameIdentifier) {
		t = xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(subject->IDPProvidedNameIdentifier)));
		xmlNodeSetName(xmlnode, "IDPProvidedNameIdentifier");
		xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));
	}

	return xmlnode;
}


static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoLibSubject *subject = LASSO_LIB_SUBJECT(node);
	struct XmlSnippet snippets[] = {
		{ "IDPProvidedNameIdentifier", 'i', (void**)&(subject->IDPProvidedNameIdentifier) },
		{ NULL, 0, NULL}
	};

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibSubject *node)
{
	node->IDPProvidedNameIdentifier = NULL;
}

static void
class_init(LassoLibSubjectClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_lib_subject_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibSubjectClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibSubject),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_SUBJECT,
				"LassoLibSubject", &this_info, 0);
	}
	return this_type;
}

LassoLibSubject*
lasso_lib_subject_new()
{
	return g_object_new(LASSO_TYPE_LIB_SUBJECT, NULL);
}

