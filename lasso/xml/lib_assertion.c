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

#include <lasso/xml/lib_assertion.h>

/*
 * Authentication assertions provided in an <AuthnResponse> element MUST be of
 * type AssertionType, which is an extension of saml:AssertionType, so that the
 * RequestID attribute from the original <AuthnRequest> MAY be included in the
 * InResponseTo attribute in the <Assertion> element. This is done because it is
 * not required that the <AuthnResponse> element itself be signed. Instead, the
 * individual <Assertion> elements contained MUST each be signed. Note that it is
 * optional for the InResponseTo to be present. Its absence indicates that the
 * <AuthnResponse> has been unilaterally sent by the identity provider without a
 * corresponding <AuthnRequest> message from the service provider. If the
 * attribute is present, it MUST be set to the RequestID of the original
 * <AuthnRequest>.
 *
 * The schema fragment is as follows:

 * <xs:element name="Assertion" type="AssertionType" substitutionGroup="saml:Assertion" />
 * <xs:complexType name="AssertionType">
 *   <xs:complexContent>
 *     <xs:extension base="saml:AssertionType">
 *       <xs:attribute name="InResponseTo" type="xs:NCName" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
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
	xmlSetProp(xmlnode, "InResponseTo", LASSO_LIB_ASSERTION(node)->InResponseTo);
	xmlSetNs(xmlnode, xmlNewNs(xmlnode, LASSO_LIB_HREF, LASSO_LIB_PREFIX));

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	int rc = 0;
	rc = parent_class->init_from_xml(node, xmlnode);
	LASSO_LIB_ASSERTION(node)->InResponseTo = xmlGetProp(xmlnode, "InResponseTo");
	return rc;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoLibAssertion *node)
{
	node->InResponseTo = NULL;
}

static void
class_init(LassoLibAssertionClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType lasso_lib_assertion_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoLibAssertionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoLibAssertion),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_ASSERTION,
				"LassoLibAssertion", &this_info, 0);
	}
	return this_type;
}

LassoLibAssertion*
lasso_lib_assertion_new_full(const char *issuer, const char *requestID,
		const char *audience, const char *notBefore, const char *notOnOrAfter)
{
	LassoSamlAssertion *assertion;

	g_return_val_if_fail(issuer != NULL, NULL);

	assertion = LASSO_SAML_ASSERTION(g_object_new(LASSO_TYPE_LIB_ASSERTION, NULL));

	assertion->AssertionID = lasso_build_unique_id(32);
	assertion->MajorVersion = LASSO_LIB_MAJOR_VERSION_N;
	assertion->MinorVersion = LASSO_LIB_MINOR_VERSION_N;
	assertion->IssueInstant = lasso_get_current_time();
	assertion->Issuer = g_strdup(issuer);
	if (requestID != NULL)
		LASSO_LIB_ASSERTION(assertion)->InResponseTo = g_strdup(requestID);

	assertion->Conditions = lasso_saml_conditions_new();
	assertion->Conditions->NotBefore = g_strdup(notBefore);
	assertion->Conditions->NotOnOrAfter = g_strdup(notOnOrAfter);
	if (audience) {
		assertion->Conditions->AudienceRestrictionCondition = 
			lasso_saml_audience_restriction_condition_new();
		assertion->Conditions->AudienceRestrictionCondition->Audience = g_strdup(audience);
	}

	return LASSO_LIB_ASSERTION(assertion);
}

