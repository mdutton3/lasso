/* $Id: sb2_usage_directive.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "sb2_usage_directive.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:sb2_usage_directive
 * @short_description: &lt;sb2:UsageDirective&gt;
 *
 * <figure><title>Schema fragment for sb2:UsageDirective</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="UsageDirectiveType">
 *   <xs:sequence>
 *     <xs:any namespace="##other" processContents="lax"
 *       maxOccurs="unbounded"/>
 *     </xs:sequence>
 *     <xs:attribute name="ref" type="xs:IDREF" use="required"/>
 *     <xs:anyAttribute namespace="##other" processContents="lax"/>
 *   </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "ref", SNIPPET_ATTRIBUTE,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UsageDirective, ref), NULL, NULL, NULL},
	{ "attributes", SNIPPET_ATTRIBUTE | SNIPPET_ANY,
		G_STRUCT_OFFSET(LassoIdWsf2Sb2UsageDirective, attributes), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2Sb2UsageDirective *node)
{
	node->attributes = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, g_free);
}

static void
class_init(LassoIdWsf2Sb2UsageDirectiveClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "UsageDirective");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_SB2_HREF, LASSO_IDWSF2_SB2_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_sb2_usage_directive_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2Sb2UsageDirectiveClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2Sb2UsageDirective),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2Sb2UsageDirective", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_sb2_usage_directive_new:
 *
 * Creates a new #LassoIdWsf2Sb2UsageDirective object.
 *
 * Return value: a newly created #LassoIdWsf2Sb2UsageDirective object
 **/
LassoIdWsf2Sb2UsageDirective*
lasso_idwsf2_sb2_usage_directive_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE, NULL);
}
