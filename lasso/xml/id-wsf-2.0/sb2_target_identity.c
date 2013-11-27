/* $Id: sb2_target_identity.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#include "../private.h"
#include "sb2_target_identity.h"
#include "idwsf2_strings.h"

/**
 * SECTION:sb2_target_identity
 * @short_description: &lt;sb2:TargetIdentity&gt;
 *
 * <figure><title>Schema fragment for sb2:TargetIdentity</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="TargetIdentityType">
 *   <xs:sequence>
 *     <xs:any namespace="##any" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
 *   </xs:sequence>
 *   <xs:anyAttribute namespace="##other" processContents="lax"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2TargetIdentity, attributes), NULL, NULL, NULL},
	{ "", SNIPPET_LIST_NODES | SNIPPET_ANY, G_STRUCT_OFFSET(LassoIdWsf2Sb2TargetIdentity, any),
		NULL, NULL, NULL },
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2Sb2TargetIdentity *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2Sb2TargetIdentityClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "TargetIdentity");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SB2_HREF, LASSO_IDWSF2_SB2_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_sb2_target_identity_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2Sb2TargetIdentityClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2Sb2TargetIdentity),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2Sb2TargetIdentity", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_sb2_target_identity_new:
 *
 * Creates a new #LassoIdWsf2Sb2TargetIdentity object.
 *
 * Return value: a newly created #LassoIdWsf2Sb2TargetIdentity object
 **/
LassoIdWsf2Sb2TargetIdentity*
lasso_idwsf2_sb2_target_identity_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SB2_TARGET_IDENTITY, NULL);
}
