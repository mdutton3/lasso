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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lasso/xml/saml-2.0/saml2_attribute_value.h>

/*
 * The schema fragment (saml-schema-assertion-2.0.xsd):
 * 
 * <element name="AttributeValue" type="anyType" nillable="true"/>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "", SNIPPET_LIST_NODES | SNIPPET_ALLOW_TEXT,
		G_STRUCT_OFFSET(LassoSaml2AttributeValue, any) },
	{ NULL, 0, 0 }
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoSaml2AttributeValue *node)
{
	node->any = NULL;
}

static void
class_init(LassoSaml2AttributeValueClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "AttributeValue");
	lasso_node_class_set_ns(nclass, LASSO_SAML2_ASSERTION_HREF, LASSO_SAML2_ASSERTION_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
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
			(GInstanceInitFunc) instance_init,
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
