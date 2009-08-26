/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
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

#include "private.h"
#include "saml_attribute_value.h"

/**
 * SECTION:saml_attribute_value
 * @short_description: value of an attribute in SAML 1.0/1.1 assertion
 * @see_also: #LassoSamlAttribute, #LassoSamlAttributeStatement, #LassoSamlAssertion
 * @include: lasso/xml/saml_attribute_value.h
 *
 * <figure><title>Schema fragment for samlp2:Extensions</title>
 * <programlisting><![CDATA[
 *
 * <element name="AttributeValue" type="anyType"/>
 *
 * ]]></programlisting>
 * </figure>
 *
 * This object support a special of specifying its content. If the <structfield>any</structfield>
 * field is %NULL, then you can attach an <type>xmlNode</type> using
 * lasso_node_set_original_xmlnode() and it will be used to generate the content of the serialized
 * <type>xmlNode</type> for this object. The content (attributes, childrent and namespaces) of the
 * <type>xmlNode</type> will be copied to the result node returned by calls to
 * lasso_node_get_xmlNode().
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES | SNIPPET_ALLOW_TEXT,
		G_STRUCT_OFFSET(LassoSamlAttributeValue, any), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	LassoSamlAttributeValue *value = LASSO_SAML_ATTRIBUTE_VALUE(node);
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
class_init(LassoSamlAttributeValueClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data->keep_xmlnode = TRUE;
	lasso_node_class_set_nodename(nclass, "AttributeValue");
	lasso_node_class_set_ns(nclass, LASSO_SAML_ASSERTION_HREF, LASSO_SAML_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_saml_attribute_value_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlAttributeValueClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlAttributeValue),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlAttributeValue",
				&this_info, 0);
	}
	return this_type;
}

LassoSamlAttributeValue*
lasso_saml_attribute_value_new()
{
	return g_object_new(LASSO_TYPE_SAML_ATTRIBUTE_VALUE, NULL);
}
