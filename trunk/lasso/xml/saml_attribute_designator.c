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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "private.h"
#include "saml_attribute_designator.h"

/**
 * SECTION:saml_attribute_designator
 * @short_description: object mapping for a saml:AttributeDesignator
 *
 * The schema fragment (oasis-sstc-saml-schema-assertion-1.1.xsd) is:
 *
 * <figure>
 * <title>Schema fragment for saml:AttributeDesignator</title>
 * <programlisting>
 * <![CDATA[
 * <element name="AttributeDesignator" type="saml:AttributeDesignatorType"/>
 * <complexType name="AttributeDesignatorType">
 *   <attribute name="AttributeName" type="string" use="required"/>
 *   <attribute name="AttributeNamespace" type="anyURI" use="required"/>
 * </complexType>
 * ]]>
 * </programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "AttributeName", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAttributeDesignator, AttributeName), NULL, NULL, NULL},
	{ "AttributeNamespace", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoSamlAttributeDesignator, AttributeNamespace), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlAttributeDesignatorClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AttributeDesignator");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_attribute_designator_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAttributeDesignatorClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAttributeDesignator),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAttributeDesignator", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_saml_attribute_designator_new:
 *
 * Creates a new #LassoSamlAttributeDesignator object.
 *
 * Return value: a newly created #LassoSamlAttributeDesignator object
 **/
LassoNode*
lasso_saml_attribute_designator_new()
{
	return g_object_new(LASSO_TYPE_SAML_ATTRIBUTE_DESIGNATOR, NULL);
}
