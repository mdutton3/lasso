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

#include <lasso/xml/saml_audience_restriction_condition.h>

/*
 * schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):
 * 
 * <element name="AudienceRestrictionCondition" type="saml:AudienceRestrictionConditionType"/>
 * <complexType name="AudienceRestrictionConditionType">
 *   <complexContent>
 *     <extension base="saml:ConditionAbstractType">
 *       <sequence>
 *         <element ref="saml:Audience" maxOccurs="unbounded"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 * 
 * <element name="Audience" type="anyURI"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

#define snippets() \
	LassoSamlAudienceRestrictionCondition *condition = \
		LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION(node); \
	struct XmlSnippet snippets[] = { \
		{ "Audience", 'c', (void**)&(condition->Audience) }, \
		{ NULL, 0, NULL} \
	};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	snippets();

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "AudienceRestrictionCondition");
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
instance_init(LassoSamlAudienceRestrictionCondition *node)
{
	node->Audience = NULL;
}

static void
class_init(LassoSamlAudienceRestrictionConditionClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_audience_restriction_condition_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAudienceRestrictionConditionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAudienceRestrictionCondition),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_CONDITION_ABSTRACT,
				"LassoSamlAudienceRestrictionCondition", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_audience_restriction_condition_new:
 * 
 * Creates a new <saml:AudienceRestrictionCondition> node object.
 * 
 * The <AudienceRestrictionCondition> element specifies that the assertion is
 * addressed to one or more specific audiences identified by <Audience>
 * elements. Although a party that is outside the audiences specified is
 * capable of drawing conclusions from an assertion, the issuer explicitly
 * makes no representation as to accuracy or trustworthiness to such a party.
 *
 * The AudienceRestrictionCondition evaluates to Valid if and only if the
 * relying party is a member of one or more of the audiences specified. The
 * issuer of an assertion cannot prevent a party to whom it is disclosed from
 * making a decision on the basis of the information provided. However, the
 * <AudienceRestrictionCondition> element allows the issuer to state explicitly
 * that no warranty is provided to such a party in a machine- and
 * human-readable form. While there can be no guarantee that a court would
 * uphold such a warranty exclusion in every circumstance, the probability of
 * upholding the warranty exclusion is considerably improved.
 *
 * Return value: the new @LassoSamlAudienceRestrictionCondition
 **/
LassoSamlAudienceRestrictionCondition*
lasso_saml_audience_restriction_condition_new()
{
	return g_object_new(LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION, NULL);
}

