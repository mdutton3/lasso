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

#include <lasso/xml/saml_conditions.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="Conditions" type="saml:ConditionsType"/>
<complexType name="ConditionsType">
  <choice minOccurs="0" maxOccurs="unbounded">
    <element ref="saml:AudienceRestrictionCondition"/>
    <element ref="saml:Condition"/>
  </choice>
  <attribute name="NotBefore" type="dateTime" use="optional"/>
  <attribute name="NotOnOrAfter" type="dateTime" use="optional"/>
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
	LassoSamlConditions *conditions = LASSO_SAML_CONDITIONS(node);

	xmlnode = xmlNewNode(NULL, "Conditions");
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX));
	if (conditions->AudienceRestrictionCondition)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(conditions->AudienceRestrictionCondition)));
	if (conditions->NotBefore)
		xmlSetProp(xmlnode, "NotBefore", conditions->NotBefore);
	if (conditions->NotOnOrAfter)
		xmlSetProp(xmlnode, "NotOnOrAfter", conditions->NotOnOrAfter);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoSamlConditions *conditions = LASSO_SAML_CONDITIONS(node);
	struct XmlSnippet snippets[] = {
		{ "AudienceRestrictionCondition", 'n',
			(void**)&(conditions->AudienceRestrictionCondition) },
		{ NULL, 0, NULL}
	};


	if (parent_class->init_from_xml(node, xmlnode))
		return -1;
	lasso_node_init_xml_with_snippets(xmlnode, snippets);
	conditions->NotBefore = xmlGetProp(xmlnode, "NotBefore");
	conditions->NotOnOrAfter = xmlGetProp(xmlnode, "NotOnOrAfter");
	return 0;
}


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlConditions *node)
{
	node->AudienceRestrictionCondition = NULL;
	node->NotBefore = NULL;
	node->NotOnOrAfter = NULL;
}

static void
class_init(LassoSamlConditionsClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_conditions_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlConditionsClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlConditions),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlConditions", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_conditions_new:
 * 
 * Creates a new <saml:Conditions> node object.
 *
 * Return value: the new @LassoSamlConditions
 **/
LassoSamlConditions*
lasso_saml_conditions_new()
{
	return g_object_new(LASSO_TYPE_SAML_CONDITIONS, NULL);
}

