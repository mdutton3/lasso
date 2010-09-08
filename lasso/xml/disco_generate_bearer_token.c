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
#include "disco_generate_bearer_token.h"
#include "./idwsf_strings.h"

/**
 * SECTION:disco_generate_bearer_token
 * @short_description: &lt;disco:DirectiveType&gt;
 *
 * <figure><title>Schema fragment for disco:DirectiveType</title>
 * <programlisting><![CDATA[
 *
 * <xs: complexType name="DirectiveType">
 *  <xs: attribute name="descriptionIDRefs" type="xs:IDREFS" use="optional"/>
 * </xs: complexType>
 * <xs: element name="GenerateBearerToken" type="disco: DirectiveType"/>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "descriptionIDRefs",SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoDiscoGenerateBearerToken, descriptionIDRefs), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoDiscoGenerateBearerTokenClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "GenerateBearerToken");
	lasso_node_class_set_ns(nclass, LASSO_DISCO_HREF, LASSO_DISCO_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_disco_generate_bearer_token_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDiscoGenerateBearerTokenClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDiscoGenerateBearerToken),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDiscoGenerateBearerToken", &this_info, 0);
	}
	return this_type;
}

LassoDiscoGenerateBearerToken*
lasso_disco_generate_bearer_token_new()
{
	LassoDiscoGenerateBearerToken *node;

	node = g_object_new(LASSO_TYPE_DISCO_GENERATE_BEARER_TOKEN, NULL);

	return node;
}
