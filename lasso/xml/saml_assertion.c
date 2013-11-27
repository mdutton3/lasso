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
#include "../utils.h"
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include "saml_assertion.h"

/**
 * SECTION:saml_assertion
 * @short_description: &lt;saml:Assertion&gt;
 *
 * <figure><title>Schema fragment for saml:Assertion</title>
 * <programlisting><![CDATA[
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
 * ]]></programlisting>
 * </figure>
 */


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Conditions", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlAssertion, Conditions), NULL, NULL, NULL},
	{ "Advice", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlAssertion, Advice), NULL, NULL, NULL},
	{ "SubjectStatement", SNIPPET_NODE,G_STRUCT_OFFSET(LassoSamlAssertion, SubjectStatement), NULL, NULL, NULL},
	{ "AuthenticationStatement", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlAssertion, AuthenticationStatement), NULL, NULL, NULL},
	{ "AttributeStatement", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoSamlAssertion, AttributeStatement), NULL, NULL, NULL},
	{ "Signature", SNIPPET_SIGNATURE,
		G_STRUCT_OFFSET(LassoSamlAssertion, AssertionID), NULL, LASSO_DS_PREFIX, LASSO_DS_HREF},
	{ "MajorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlAssertion, MajorVersion), NULL, NULL, NULL},
	{ "MinorVersion", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER,
		G_STRUCT_OFFSET(LassoSamlAssertion, MinorVersion), NULL, NULL, NULL},
	{ "AssertionID", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, AssertionID), NULL, NULL, NULL},
	{ "Issuer", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, Issuer), NULL, NULL, NULL},
	{ "IssueInstant", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoSamlAssertion, IssueInstant), NULL, NULL, NULL},

	/* hidden fields; use in lasso dumps */
	{ "SignType", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, sign_type), NULL, NULL, NULL},
	{ "SignMethod", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, sign_method), NULL, NULL, NULL},
	{ "PrivateKeyFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, private_key_file), NULL, NULL, NULL},
	{ "CertificateFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoSamlAssertion, certificate_file), NULL, NULL, NULL},

	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static void
insure_namespace(xmlNode *xmlnode, xmlNs *ns)
{
	/* insure children are kept in saml namespace */
	xmlNode *t;
	xmlNs *xsi_ns;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}

		if (xmlnode->ns && strcmp((char*)xmlnode->ns->href, LASSO_LIB_HREF) == 0) {
			char *typename, *gtypename;
			GType gtype;

			typename = g_strdup_printf("lib:%sType", xmlnode->name);
			gtypename = g_strdup_printf("LassoSaml%s", xmlnode->name);
			gtype = g_type_from_name(gtypename);

			if (gtype) {
				xmlSetNs(xmlnode, ns);
				if (xmlHasNsProp(t, (xmlChar*)"type",
							(xmlChar*)LASSO_XSI_HREF) == NULL) {
					xsi_ns = xmlNewNs(xmlnode, (xmlChar*)LASSO_XSI_HREF,
							(xmlChar*)LASSO_XSI_PREFIX);
					xmlNewNsProp(xmlnode, xsi_ns, (xmlChar*)"type",
							(xmlChar*)typename);
				}
			}
			lasso_release(gtypename);
			lasso_release(typename);
		}

		insure_namespace(t, ns);

		t = t->next;
	}
}


static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;
	xmlNs *ns;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	ns = xmlSearchNs(NULL, xmlnode, (xmlChar*)"saml");
	insure_namespace(xmlnode, ns);

	return xmlnode;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

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
	nclass->node_data->id_attribute_name = "AssertionID";
	nclass->node_data->id_attribute_offset = G_STRUCT_OFFSET(LassoSamlAssertion, AssertionID);
	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(LassoSamlAssertion, sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(LassoSamlAssertion, sign_method);
	nclass->node_data->private_key_file_offset = G_STRUCT_OFFSET(LassoSamlAssertion,
			private_key_file);
	nclass->node_data->certificate_file_offset = G_STRUCT_OFFSET(LassoSamlAssertion, certificate_file);
	nclass->node_data->keep_xmlnode = TRUE;
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
			NULL,
			NULL,
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAssertion", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_assertion_new:
 *
 * Creates a new #LassoSamlAssertion object.
 *
 * Return value: a newly created #LassoSamlAssertion object
 **/
LassoSamlAssertion*
lasso_saml_assertion_new()
{
	return g_object_new(LASSO_TYPE_SAML_ASSERTION, NULL);
}
