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

#include <lasso/xml/saml_assertion.h>

/*
The schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):

<element name="Assertion" type="saml:AssertionType"/>
<complexType name="AssertionType">
  <sequence>
    <element ref="saml:Conditions" minOccurs="0"/>
    <element ref="saml:Advice" minOccurs="0"/>
    <choice maxOccurs="unbounded">
      <element ref="saml:Statement"/>
      <element ref="saml:SubjectStatement"/>
      <element ref="saml:AuthenticationStatement"/>
      <element ref="saml:AuthorizationDecisionStatement"/>
      <element ref="saml:AttributeStatement"/>
    </choice>
    <element ref="ds:Signature" minOccurs="0"/>
  </sequence>
  <attribute name="MajorVersion" type="integer" use="required"/>
  <attribute name="MinorVersion" type="integer" use="required"/>
  <attribute name="AssertionID" type="saml:IDType" use="required"/>
  <attribute name="Issuer" type="string" use="required"/>
  <attribute name="IssueInstant" type="dateTime" use="required"/>
</complexType>

From oasis-sstc-saml-schema-assertion-1.0.xsd:
<simpleType name="IDType">
  <restriction base="string"/>
</simpleType>
*/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

void
lasso_saml_assertion_add_authenticationStatement(LassoSamlAssertion *node,
						 LassoSamlAuthenticationStatement *authenticationStatement)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(LASSO_IS_SAML_AUTHENTICATION_STATEMENT(authenticationStatement));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(authenticationStatement), TRUE);
}

void
lasso_saml_assertion_add_statement(LassoSamlAssertion *node,
				   LassoSamlStatementAbstract *statement)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(LASSO_IS_SAML_STATEMENT_ABSTRACT(statement));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(statement), TRUE);
}

void
lasso_saml_assertion_add_subjectStatement(LassoSamlAssertion *node,
					  LassoSamlSubjectStatementAbstract *subjectStatement)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(LASSO_IS_SAML_SUBJECT_STATEMENT_ABSTRACT(subjectStatement));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(subjectStatement), TRUE);
}

/**
 * lasso_saml_assertion_set_advice:
 * @node: the <saml:Assertion> node object
 * @advice: the <saml:Advice> node object
 * 
 * Sets the <Advice> element [optional].
 *
 * Additional information related to the assertion that assists processing in
 * certain situations but which MAY be ignored by applications that do not
 * support its use.
 **/
void
lasso_saml_assertion_set_advice(LassoSamlAssertion *node,
				LassoSamlAdvice *advice)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(LASSO_IS_SAML_ADVICE(advice));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(advice), FALSE);
}

/**
 * lasso_saml_assertion_set_assertionID:
 * @node: the <saml:Assertion> node object
 * @assertionID: the value of "AssertionID" attribute
 * 
 * Sets the "AssertionID" attribute [required].
 *
 * The identifier for this assertion. It is of type IDType, and MUST follow the
 * requirements specified by that type for identifier uniqueness.
 **/
void
lasso_saml_assertion_set_assertionID(LassoSamlAssertion *node,
				     const xmlChar *assertionID)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(assertionID != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "AssertionID", assertionID);
}

/**
 * lasso_saml_assertion_set_conditions:
 * @node: the <saml:Assertion> node object
 * @conditions: the <saml:Conditions> node object
 * 
 * Sets the <Conditions> element [optional].
 *
 * Conditions that MUST be taken into account in assessing the validity of the
 * assertion.
 **/
void
lasso_saml_assertion_set_conditions(LassoSamlAssertion *node,
				    LassoSamlConditions *conditions)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(LASSO_IS_SAML_CONDITIONS(conditions));

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->add_child(LASSO_NODE (node), LASSO_NODE(conditions), FALSE);
}

/**
 * lasso_saml_assertion_set_issueInstance:
 * @node: the <saml:Assertion> node object
 * @issueInstance: the value of "IssueInstance" attribute
 * 
 * Sets the "IssueInstance" attribute [required].
 *
 * The time instant of issue in UTC as described in Section 1.2.2
 * (oasis-sstc-saml-core-1.0.pdf).
 **/
void
lasso_saml_assertion_set_issueInstance(LassoSamlAssertion *node,
				       const xmlChar *issueInstance)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(issueInstance != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "IssueInstance", issueInstance);
}

/**
 * lasso_saml_assertion_set_issuer:
 * @node: the <saml:Assertion> node object
 * @issuer: the value of "Issuer" attribute
 * 
 * Sets the "Issuer" attribute [required].
 *
 * The issuer of the assertion. The name of the issuer is provided as a string.
 * The issuer name SHOULD be unambiguous to the intended relying parties. SAML
 * authorities may use an identifier such as a URI reference that is designed
 * to be unambiguous regardless of context.
 **/
void
lasso_saml_assertion_set_issuer(LassoSamlAssertion *node,
				const xmlChar *issuer)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(issuer != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "Issuer", issuer);
}

/**
 * lasso_saml_assertion_set_majorVersion:
 * @node: the <saml:Assertion> node object
 * @majorVersion: the value of "MajorVersion" attribute
 * 
 * Sets the "MajorVersion" attribute [required].
 *
 * The major version of the assertion. The identifier for the version of SAML
 * defined in this specification is 1. Processing of this attribute is
 * specified in Section 3.4.4 (oasis-sstc-saml-core-1.0.pdf).
 **/
void
lasso_saml_assertion_set_majorVersion(LassoSamlAssertion *node,
				      const xmlChar *majorVersion)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(majorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MajorVersion", majorVersion);
}

/**
 * lasso_saml_assertion_set_minorVersion:
 * @node: the <saml:Assertion> node object
 * @minorVersion: the value of "MinorVersion" attribute
 * 
 * Sets the "MinorVersion" attribute [required].
 *
 * The minor version of the assertion. The identifier for the version of SAML
 * defined in this specification is 0. Processing of this attribute is
 * specified in Section 3.4.4 (oasis-sstc-saml-core-1.0.pdf).
 **/
void
lasso_saml_assertion_set_minorVersion(LassoSamlAssertion *node,
				      const xmlChar *minorVersion)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(minorVersion != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  class->set_prop(LASSO_NODE (node), "MinorVersion", minorVersion);
}

gint
lasso_saml_assertion_set_signature(LassoSamlAssertion *node,
				   gint                sign_method,
				   const xmlChar      *private_key_file,
				   const xmlChar      *certificate_file)
{
  g_assert(LASSO_IS_SAML_ASSERTION(node));
  g_assert(private_key_file != NULL);
  g_assert(certificate_file != NULL);

  LassoNodeClass *class = LASSO_NODE_GET_CLASS(node);
  return (class->add_signature(LASSO_NODE (node), sign_method,
			       private_key_file, certificate_file));
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_saml_assertion_instance_init(LassoSamlAssertion *node)
{
  LassoNodeClass *class = LASSO_NODE_GET_CLASS(LASSO_NODE(node));

  class->set_ns(LASSO_NODE(node), lassoSamlAssertionHRef,
		lassoSamlAssertionPrefix);
  class->set_name(LASSO_NODE(node), "Assertion");
}

static void
lasso_saml_assertion_class_init(LassoSamlAssertionClass *klass)
{
}

GType lasso_saml_assertion_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoSamlAssertionClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_saml_assertion_class_init,
      NULL,
      NULL,
      sizeof(LassoSamlAssertion),
      0,
      (GInstanceInitFunc) lasso_saml_assertion_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoSamlAssertion",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_saml_assertion_new:
 * 
 * Creates a new <saml:Assertion> node object.
 * 
 * Return value: the new @LassoSamlAssertion
 **/
LassoNode* lasso_saml_assertion_new()
{
  return LASSO_NODE(g_object_new(LASSO_TYPE_SAML_ASSERTION, NULL));
}
