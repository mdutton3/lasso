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
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	/* insure children are kept in saml namespace */
	char *typename;
	xmlNode *t;
	xmlNs *xsi_ns;

	xsi_ns = xmlNewNs(xmlnode, LASSO_XSI_HREF, LASSO_XSI_PREFIX);

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		
		if (xmlnode->ns && strcmp(xmlnode->ns->href, LASSO_LIB_HREF) == 0) {
			typename = g_strdup_printf("lib:%sType", xmlnode->name);
			xmlSetNs(xmlnode, ns);
			xmlNewNsProp(xmlnode, xsi_ns, "type", typename);
			g_free(typename);
		}

		insure_namespace(t, ns);

		t = t->next;
	}
}


static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoSamlAssertion *assertion = LASSO_SAML_ASSERTION(node);
	xmlNs *ns;
	char s[10];

	xmlnode = xmlNewNode(NULL, "Assertion");
	xmlSetProp(xmlnode, "AssertionID", assertion->AssertionID);
	ns = xmlNewNs(xmlnode, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	xmlSetNs(xmlnode, ns);
	snprintf(s, 9, "%d", assertion->MajorVersion);
	xmlSetProp(xmlnode, "MajorVersion", s);
	snprintf(s, 9, "%d", assertion->MinorVersion);
	xmlSetProp(xmlnode, "MinorVersion", s);
	if (assertion->Issuer)
		xmlSetProp(xmlnode, "Issuer", assertion->Issuer);
	if (assertion->IssueInstant)
		xmlSetProp(xmlnode, "IssueInstant", assertion->IssueInstant);

	if (assertion->Conditions)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(assertion->Conditions)));
	if (assertion->Advice)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(LASSO_NODE(assertion->Advice)));
	if (assertion->AuthenticationStatement)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(assertion->AuthenticationStatement)));
	if (assertion->SubjectStatement)
		xmlAddChild(xmlnode, lasso_node_get_xmlNode(
					LASSO_NODE(assertion->SubjectStatement)));

	insure_namespace(xmlnode, ns);

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	char *s;
	LassoSamlAssertion *assertion = LASSO_SAML_ASSERTION(node);
	struct XmlSnippet snippets[] = {
		{ "Conditions", 'n', (void**)&(assertion->Conditions) }, 
		{ "Advice", 'n', (void**)&(assertion->Advice) }, 
		{ "SubjectStatement", 'n', (void**)&(assertion->SubjectStatement) }, 
		{ "AuthenticationStatement", 'n', (void**)&(assertion->AuthenticationStatement) }, 
		{ NULL, 0, NULL}
	};

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	assertion->AssertionID = xmlGetProp(xmlnode, "AssertionID");
	assertion->Issuer = xmlGetProp(xmlnode, "Issuer");
	assertion->IssueInstant = xmlGetProp(xmlnode, "IssueInstant");
	s = xmlGetProp(xmlnode, "MajorVersion");
	if (s) {
		assertion->MajorVersion = atoi(s);
		xmlFree(s);
	}
	s = xmlGetProp(xmlnode, "MinorVersion");
	if (s) {
		assertion->MinorVersion = atoi(s);
		xmlFree(s);
	}

	lasso_node_init_xml_with_snippets(xmlnode, snippets);

	return 0;
}


gint
lasso_saml_assertion_set_signature(LassoSamlAssertion  *node,
				   gint                 sign_method,
				   const xmlChar       *private_key_file,
				   const xmlChar       *certificate_file)
{
	return 0;
#if 0 /* XXX: signatures are done differently */
  gint ret;
  LassoNodeClass *class;

  g_return_val_if_fail(LASSO_IS_SAML_ASSERTION(node),
		       LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);

  class = LASSO_NODE_GET_CLASS(node);

  ret = class->add_signature(LASSO_NODE (node), sign_method,
			     private_key_file, certificate_file);

  return ret;
#endif
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSamlAssertion *node)
{
}

static void
class_init(LassoSamlAssertionClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);
	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;
}

GType
lasso_saml_assertion_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAssertionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAssertion),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAssertion", &this_info, 0);
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
LassoNode*
lasso_saml_assertion_new()
{
	return g_object_new(LASSO_TYPE_SAML_ASSERTION, NULL);
}

