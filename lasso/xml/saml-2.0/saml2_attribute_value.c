/* $Id: saml2_attribute_value.c 2820 2006-10-09 10:09:25Z dlaniel $
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
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

#include "../private.h"
#include "saml2_attribute_value.h"

/**
 * SECTION:saml2_attribute_value
 * @short_description: value of an attribute in a SAML 2.0 assertion
 * @see_also: #LassoSaml2Attribute, #LassoSaml2AttributeStatement, #LassoSaml2Assertion
 *
 * <figure><title>Schema fragment from saml-schema-assertion-2.0.xsd)</title>
 * <programlisting><![CDATA[
 *
 * <element name="AttributeValue" type="anyType" nillable="true"/>
 *
 * ]]></programlisting>
 * </figure>
 *
 * This object support a special of specifying its content. If the <structfield>any</structfield>
 * attribute is %NULL, then you can attach an <type>xmlNode</type> using
 * lasso_node_set_original_xmlnode() and it will be used to generate the content of the serialized
 * <type>xmlNode</type> for this object. The content (attributes, childrent and namespaces) of the
 * node will be copied to the result node created by a call to lasso_node_get_xmlNode().
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

struct _LassoSaml2AttributeValuePrivate {
	GHashTable *any_attributes;
};

static struct XmlSnippet schema_snippets[] = {
	{ "any", SNIPPET_LIST_NODES | SNIPPET_ANY | SNIPPET_ALLOW_TEXT,
		G_STRUCT_OFFSET(LassoSaml2AttributeValue, any), NULL, NULL, NULL},
	{ "any_attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY | SNIPPET_PRIVATE,
		G_STRUCT_OFFSET(struct _LassoSaml2AttributeValuePrivate, any_attributes), NULL,
		NULL, NULL },
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoSaml2AttributeValue *value = LASSO_SAML2_ATTRIBUTE_VALUE(node);
	LassoNodeClass *parent_class = NULL;
	xmlNode *cur;

	parent_class = g_type_class_peek_parent(LASSO_NODE_GET_CLASS(node));
	cur = parent_class->get_xmlNode(node, lasso_dump);

	if (value->any) {
		return cur;
	} else {
		return lasso_node_get_xmlnode_for_any_type(node, cur);
	}
}

static void
class_init(LassoSaml2AttributeValueClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data->keep_xmlnode = TRUE;
	lasso_node_class_set_nodename(nclass, "AttributeValue");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(struct _LassoSaml2AttributeValuePrivate));
}

GType
lasso_saml2_attribute_value_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSaml2AttributeValueClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSaml2AttributeValue),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSaml2AttributeValue",
				&this_info, 0);
	}
	return this_type;
}

LassoSaml2AttributeValue*
lasso_saml2_attribute_value_new()
{
	return g_object_new(LASSO_TYPE_SAML2_ATTRIBUTE_VALUE, NULL);
}
