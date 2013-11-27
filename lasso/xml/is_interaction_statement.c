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
#include "is_interaction_statement.h"
#include "idwsf_strings.h"

/**
 * SECTION:is_interaction_statement
 * @short_description: &lt;is:InteractionStatementType&gt;
 *
 * <figure><title>Schema fragment for is:InteractionStatementType</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="InteractionStatementType">
 *   <xs:sequence>
 *     <xs:element ref="Inquiry"/>
 *     <xs:element ref="ds:Signature"/>
 *   </xs:sequence>
 * </xs:complexType>
 *
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "Inquiry", SNIPPET_NODE, G_STRUCT_OFFSET(LassoIsInteractionStatement, Inquiry), NULL,
		NULL, NULL},
	{ "Signature", SNIPPET_SIGNATURE, 0, NULL, LASSO_DS_PREFIX, LASSO_DS_HREF },
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIsInteractionStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "InteractionStatement");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_interaction_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsInteractionStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsInteractionStatement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsInteractionStatement", &this_info, 0);
	}
	return this_type;
}

LassoIsInteractionStatement*
lasso_is_interaction_statement_new(LassoIsInquiry *inquiry)
{
	LassoIsInteractionStatement *node;

	node = g_object_new(LASSO_TYPE_IS_INTERACTION_STATEMENT, NULL);

	node->Inquiry = inquiry;

	return node;
}
