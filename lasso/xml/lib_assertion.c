/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "private.h"
#include "lib_assertion.h"
#include "../registry.h"

/**
 * SECTION:lib_assertion
 * @short_description: &lt;lib:Assertion&gt;
 *
 * <blockquote>
 * Authentication assertions provided in an AuthnResponse element MUST be of
 * type AssertionType, which is an extension of saml:AssertionType, so that the
 * RequestID attribute from the original AuthnRequest MAY be included in the
 * InResponseTo attribute in the Assertion element. This is done because it is
 * not required that the AuthnResponse element itself be signed. Instead, the
 * individual Assertion elements contained MUST each be signed. Note that it is
 * optional for the InResponseTo to be present. Its absence indicates that the
 * AuthnResponse has been unilaterally sent by the identity provider without a
 * corresponding AuthnRequest message from the service provider. If the
 * attribute is present, it MUST be set to the RequestID of the original
 * AuthnRequest.
 * </blockquote>
 *
 * <figure><title>Schema fragment for lib:Assertion</title>
 * <programlisting><![CDATA[
 * <xs:element name="Assertion" type="AssertionType" substitutionGroup="saml:Assertion" />
 * <xs:complexType name="AssertionType">
 *   <xs:complexContent>
 *     <xs:extension base="saml:AssertionType">
 *       <xs:attribute name="InResponseTo" type="xs:NCName" use="optional"/>
 *     </xs:extension>
 *   </xs:complexContent>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "InResponseTo", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoLibAssertion, InResponseTo), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoLibAssertionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->node_data->xsi_sub_type = TRUE;
	lasso_node_class_set_nodename(nclass, "AssertionType");
	lasso_node_class_set_ns(nclass, LASSO_LIB_HREF, LASSO_LIB_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_lib_assertion_get_type()
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
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_ASSERTION,
				"LassoLibAssertion", &this_info, 0);
		lasso_registry_default_add_direct_mapping(LASSO_LIB_HREF, "AssertionType",
				LASSO_LASSO_HREF, "LassoLibAssertion");
	}
	return this_type;
}

/**
 * lasso_lib_assertion_new:
 *
 * Creates a new #LassoLibAssertion object.
 *
 * Return value: a newly created #LassoLibAssertion object
 **/
LassoLibAssertion*
lasso_lib_assertion_new()
{
	return g_object_new(LASSO_TYPE_LIB_ASSERTION, NULL);
}

/**
 * lasso_lib_assertion_new_full:
 * @issuer: the issuer entityID string
 * @requestID:(allow-none): the identifier of the request which initiated the creation of this
 * assertion
 * @audience:(allow-none): the entityID of the receiver of this assertion
 * @notBefore: a timestamp formatted as iso-8601
 * @notOnOrAfter: a timestamp formatted as iso-8601
 *
 * Creates a new #LassoLibAssertion object and initializes its Issuer, InResponseTo,
 * AudienceRestrictionCondition, notBefore and notOnOrAfter fields or attributes.
 *
 * Return value: a newly created #LassoLibAssertion object
 **/
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
		assertion->Conditions->AudienceRestrictionCondition = g_list_append(NULL,
			lasso_saml_audience_restriction_condition_new_full(audience));
	}

	return LASSO_LIB_ASSERTION(assertion);
}
