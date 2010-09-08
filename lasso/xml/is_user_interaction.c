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
#include "is_user_interaction.h"
#include "./idwsf_strings.h"

/**
 * SECTION:is_user_interaction
 * @short_description: &lt;is:UserInteraction&gt;
 *
 * <figure><title>Schema fragment for is:UserInteraction</title>
 * <programlisting><![CDATA[
 *
 * <xs:element name="UserInteraction" type="UserInteractionHeaderType"/>
 * <xs:complexType name="UserInteractionHeaderType">
 *   <xs:sequence>
 *     <xs:element name="InteractionService" type="disco:ResourceOfferingType" minOccurs="0"/>
 *   </xs:sequence>
 *   <xs:attribute name="id" type="xs:ID" use="optional"/>
 *   <xs:attribute name="interact" type="xs:QName" use="optional" default="is:interactIfNeeded"/>
 *   <xs:attribute name="language" type="xs:NMTOKENS" use="optional"/>
 *   <xs:attribute name="redirect" type="xs:boolean" use="optional" default="0"/>
 *   <xs:attribute name="maxInteractTime" type="xs:integer" use="optional"/>
 *   <xs:attribute ref="soap:actor" use="optional"/>
 *   <xs:attribute ref="soap:mustUnderstand" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "InteractionService", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIsUserInteraction, InteractionService), NULL, NULL, NULL},
	{ "id", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsUserInteraction, id), NULL, NULL, NULL},
	{ "interact", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsUserInteraction, interact), NULL, NULL, NULL},
	{ "language", SNIPPET_ATTRIBUTE, G_STRUCT_OFFSET(LassoIsUserInteraction, language), NULL, NULL, NULL},
	{ "redirect", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN,
		G_STRUCT_OFFSET(LassoIsUserInteraction, redirect), NULL, NULL, NULL},
	{ "maxInteractTime", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIsUserInteraction, maxInteractTime), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIsUserInteraction *node)
{
	node->interact = g_strdup(LASSO_IS_INTERACT_ATTR_INTERACT_IF_NEEDED);
}

static void
class_init(LassoIsUserInteractionClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "UserInteraction");
	lasso_node_class_set_ns(nclass, LASSO_IS_HREF, LASSO_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_is_user_interaction_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIsUserInteractionClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIsUserInteraction),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIsUserInteraction", &this_info, 0);
	}
	return this_type;
}

LassoIsUserInteraction*
lasso_is_user_interaction_new()
{
	LassoIsUserInteraction *node;

	node = g_object_new(LASSO_TYPE_IS_USER_INTERACTION, NULL);

	return node;
}
