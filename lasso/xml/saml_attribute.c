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
#include "saml_attribute.h"

/*
 * SECTION:saml_attribute
 * @short_description: Mapping of the SAML element containing an attribute
 * @stability: Stable
 *
 * The schema fragment (oasis-sstc-saml-schema-assertion-1.1.xsd):
 * <figure><title>Schema fragment for saml:Attribute</title>
 * <programlisting><![CDATA[
 * <element name="Attribute" type="saml:AttributeType"/>
 * <complexType name="AttributeType">
 *   <complexContent>
 *     <extension base="saml:AttributeDesignatorType">
 *       <sequence>
 *         <element ref="saml:AttributeValue" maxOccurs="unbounded"/>
 *       </sequence>
 *     </extension>
 *   </complexContent>
 * </complexType>
 *
 * <element name="AttributeValue" type="anyType"/>
 *
 * <xs:complexType name="anyType" mixed="true">
 *   <xs:annotation>
 *     <xs:documentation>
 *     Not the real urType, but as close an approximation as we can
 *     get in the XML representation</xs:documentation>
 *   </xs:annotation>
 *   <xs:sequence>
 *     <xs:any minOccurs="0" maxOccurs="unbounded" processContents="lax"/>
 *   </xs:sequence>
 *   <xs:anyAttribute processContents="lax"/>
 * </xs:complexType>
 *
 * <element name="AttributeDesignator" type="saml:AttributeDesignatorType"/>
 * <complexType name="AttributeDesignatorType">
 *   <attribute name="AttributeName" type="string" use="required"/>
 *   <attribute name="AttributeNamespace" type="anyURI" use="required"/>
 * </complexType>
 * ]]></programlisting>
 * </figure>
 *
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AttributeName", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAttribute, attributeName), NULL, NULL, NULL},
	{ "AttributeNameSpace", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAttribute, attributeNameSpace), NULL, NULL, NULL},
	{ "AttributeValue", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoSamlAttribute, AttributeValue), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlAttributeClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Attribute");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_attribute_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAttributeClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAttribute),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_SAML_ATTRIBUTE_DESIGNATOR,
				"LassoSamlAttribute", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_attribute_new:
 *
 * Creates a new #LassoSamlAttribute object.
 *
 * Return value: a newly created #LassoSamlAttribute object
 **/
LassoSamlAttribute*
lasso_saml_attribute_new()
{
	return g_object_new(LASSO_TYPE_SAML_ATTRIBUTE, NULL);
}
