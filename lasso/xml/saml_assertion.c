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
 * Schema fragment (oasis-sstc-saml-schema-assertion-1.0.xsd):
 * 
 * <element name="Assertion" type="saml:AssertionType"/>
 * <complexType name="AssertionType">
 *   <sequence>
 *     <element ref="saml:Conditions" minOccurs="0"/>
 *     <element ref="saml:Advice" minOccurs="0"/>
 *     <choice maxOccurs="unbounded">
 *       <element ref="saml:Statement"/>
 *       <element ref="saml:SubjectStatement"/>
 *       <element ref="saml:AuthenticationStatement"/>
 *       <element ref="saml:AuthorizationDecisionStatement"/>
 *       <element ref="saml:AttributeStatement"/>
 *     </choice>
 *     <element ref="ds:Signature" minOccurs="0"/>
 *   </sequence>
 *   <attribute name="MajorVersion" type="integer" use="required"/>
 *   <attribute name="MinorVersion" type="integer" use="required"/>
 *   <attribute name="AssertionID" type="saml:IDType" use="required"/>
 *   <attribute name="Issuer" type="string" use="required"/>
 *   <attribute name="IssueInstant" type="dateTime" use="required"/>
 * </complexType>
 * 
 * From oasis-sstc-saml-schema-assertion-1.0.xsd:
 * <simpleType name="IDType">
 *   <restriction base="string"/>
 * </simpleType>
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Conditions", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlAssertion, Conditions) },
	{ "Advice", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlAssertion, Advice) },
	{ "SubjectStatement", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlAssertion, SubjectStatement) },
	{ "AuthenticationStatement", SNIPPET_NODE, 
		G_STRUCT_OFFSET(LassoSamlAssertion, AuthenticationStatement) },
	{ "MajorVersion", SNIPPET_ATTRIBUTE_INT,
		G_STRUCT_OFFSET(LassoSamlAssertion, MajorVersion) },
	{ "MinorVersion", SNIPPET_ATTRIBUTE_INT,
		G_STRUCT_OFFSET(LassoSamlAssertion, MinorVersion) },
	{ "AssertionID", SNIPPET_ATTRIBUTE, 
		G_STRUCT_OFFSET(LassoSamlAssertion, AssertionID) },
	{ "Issuer", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, Issuer) },
	{ "IssueInstant", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAssertion, IssueInstant) },
	{ NULL, 0, 0}
};

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
			if (xmlHasNsProp(t, "type", LASSO_XSI_HREF) == NULL) {
				xmlNewNsProp(xmlnode, xsi_ns, "type", typename);
			}
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
	xmlNs *ns;
	
	xmlnode = parent_class->get_xmlNode(node);
	ns = xmlSearchNs(NULL, xmlnode, "saml");
	insure_namespace(xmlnode, ns);

	return xmlnode;
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
instance_init(LassoSamlAssertion *assertion)
{
}

static void
class_init(LassoSamlAssertionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);
	
	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Assertion");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
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

