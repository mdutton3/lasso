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

#include <lasso/xml/saml_subject.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="Subject" type="saml:SubjectType"/>
<complexType name="SubjectType">
  <choice>
    <sequence>
      <element ref="saml:NameIdentifier"/>
      <element ref="saml:SubjectConfirmation" minOccurs="0"/>
    </sequence>
    <element ref="saml:SubjectConfirmation"/>
  </choice>
</complexType>
*/

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	LassoSamlSubject *subject = LASSO_SAML_SUBJECT(node);
	xmlNode *xmlnode;

	xmlnode = xmlNewNode(NULL, "Subject");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX));

	if (subject->NameIdentifier)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(subject->NameIdentifier)));

	if (subject->SubjectConfirmation)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(subject->SubjectConfirmation)));

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	xmlNode *t;
	LassoSamlSubject *subject = LASSO_SAML_SUBJECT(node);

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "NameIdentifier") == 0) {
			subject->NameIdentifier = LASSO_SAML_NAME_IDENTIFIER(
					lasso_node_new_from_xmlNode(t));
		}
		if (strcmp(t->name, "SubjectConfirmation") == 0) {
			subject->SubjectConfirmation = LASSO_SAML_SUBJECT_CONFIRMATION(
					lasso_node_new_from_xmlNode(t));
		}
		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlSubject *node)
{
	node->NameIdentifier = NULL;
	node->SubjectConfirmation = NULL;
}

static void
class_init(LassoSamlSubjectClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_subject_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlSubjectClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlSubject),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlSubject", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_subject_new:
 * 
 * Creates a new <saml:Subject> node object.
 *
 * Return value: the new @LassoSamlSubject
 **/
LassoNode* lasso_saml_subject_new()
{
	return g_object_new(LASSO_TYPE_SAML_SUBJECT, NULL);
}

