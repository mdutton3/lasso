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

#include <lasso/xml/saml_subject_confirmation.h>

/*
 * Schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):
 * 
 * <element name="SubjectConfirmation" type="saml:SubjectConfirmationType"/>
 * <complexType name="SubjectConfirmationType">
 *   <sequence>
 *     <element ref="saml:ConfirmationMethod" maxOccurs="unbounded"/>
 *     <element ref="saml:SubjectConfirmationData" minOccurs="0"/>
 *     <element ref="ds:KeyInfo" minOccurs="0"/>
 *   </sequence>
 * </complexType>
 * 
 * <element name="SubjectConfirmationData" type="anyType"/>
 * <element name="ConfirmationMethod" type="anyURI"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoSamlSubjectConfirmation *confirm = LASSO_SAML_SUBJECT_CONFIRMATION(node); \
	struct XmlSnippet snippets[] = { \
		{ "ConfirmationMethod", 'c', (void**)&(confirm->ConfirmationMethod) }, \
		{ "SubjectConfirmationData", 'c', (void**)&(confirm->SubjectConfirmationData) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = xmlNewNode(NULL, "SubjectConfirmation");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, 
				LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX));
	lasso_node_build_xml_with_snippets(xmlnode, snippets);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	snippets();

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlSubjectConfirmation *node)
{
}

static void
class_init(LassoSamlSubjectConfirmationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_subject_confirmation_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlSubjectConfirmationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlSubjectConfirmation),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlSubjectConfirmation", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_subject_confirmation_new:
 * 
 * Creates a new <saml:SubjectConfirmation> node object.
 * 
 * Return value: the new @LassoSamlSubjectConfirmation
 **/
LassoSamlSubjectConfirmation*
lasso_saml_subject_confirmation_new()
{
	return g_object_new(LASSO_TYPE_SAML_SUBJECT_CONFIRMATION, NULL);
}
