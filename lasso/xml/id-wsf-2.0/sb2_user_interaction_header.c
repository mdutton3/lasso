/* $Id: sb2_user_interaction_header.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "sb2_user_interaction_header.h"
#include "./idwsf2_strings.h"
#include "../../registry.h"

/**
 * SECTION:sb2_user_interaction_header
 * @short_description: &lt;sb2:UserInteractionHeader&gt;
 *
 * <figure><title>Schema fragment for sb2:UserInteractionHeader</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="UserInteractionHeaderType">
 *   <xs:sequence>
 *     <xs:element name="InteractionService" type="wsa:EndpointReferenceType"
 *             minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:attribute name="interact" type="xs:string" use="optional"
 *           default="interactIfNeeded"/>
 *   <xs:attribute name="language" type="xs:NMTOKENS" use="optional"/>
 *   <xs:attribute name="redirect" type="xs:boolean" use="optional" default="0"/>
 *   <xs:attribute name="maxInteractTime" type="xs:integer" use="optional"/>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "InteractionService", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UserInteractionHeader, InteractionService), NULL, NULL, NULL},
	{ "interact", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UserInteractionHeader, interact), NULL, NULL, NULL},
	{ "language", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UserInteractionHeader, language), NULL, NULL, NULL},
	{ "redirect", SNIPPET_ATTRIBUTE | SNIPPET_BOOLEAN | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UserInteractionHeader, redirect), NULL, NULL, NULL},
	{ "maxInteractTime", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UserInteractionHeader, maxInteractTime), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UserInteractionHeader, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2Sb2UserInteractionHeader *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2Sb2UserInteractionHeaderClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "UserInteraction");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SB2_HREF, LASSO_IDWSF2_SB2_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_sb2_user_interaction_header_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2Sb2UserInteractionHeaderClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2Sb2UserInteractionHeader),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2Sb2UserInteractionHeader", &this_info, 0);
		lasso_registry_default_add_direct_mapping(LASSO_IDWSF2_SB2_HREF, "UserInteraction",
				LASSO_LASSO_HREF, "LassoIdWsf2Sb2UserInteractionHeader");
	}
	return this_type;
}

/**
 * lasso_idwsf2_sb2_user_interaction_header_new:
 *
 * Creates a new #LassoIdWsf2Sb2UserInteractionHeader object.
 *
 * Return value: a newly created #LassoIdWsf2Sb2UserInteractionHeader object
 **/
LassoIdWsf2Sb2UserInteractionHeader*
lasso_idwsf2_sb2_user_interaction_header_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SB2_USER_INTERACTION_HEADER, NULL);
}
