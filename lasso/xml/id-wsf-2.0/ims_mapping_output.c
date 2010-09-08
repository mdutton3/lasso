/* $Id: ims_mapping_output.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include "ims_mapping_output.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:ims_mapping_output
 * @short_description: &lt;ims:MappingOutput&gt;
 *
 * <figure><title>Schema fragment for ims:MappingOutput</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="MappingOutputType">
 *   <xs:sequence>
 *     <xs:element ref="sec:Token"/>
 *   </xs:sequence>
 *   <xs:attribute name="reqRef" type="lu:IDReferenceType" use="optional"/>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Token", SNIPPET_NODE,
		G_STRUCT_OFFSET(LassoIdWsf2ImsMappingOutput, Token), NULL, NULL, NULL},
	{ "reqRef", SNIPPET_ATTRIBUTE | SNIPPET_OPTIONAL,
		G_STRUCT_OFFSET(LassoIdWsf2ImsMappingOutput, reqRef), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoIdWsf2ImsMappingOutputClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "MappingOutput");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_IMS_HREF, LASSO_IDWSF2_IMS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_idwsf2_ims_mapping_output_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2ImsMappingOutputClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2ImsMappingOutput),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2ImsMappingOutput", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_ims_mapping_output_new:
 *
 * Creates a new #LassoIdWsf2ImsMappingOutput object.
 *
 * Return value: a newly created #LassoIdWsf2ImsMappingOutput object
 **/
LassoIdWsf2ImsMappingOutput*
lasso_idwsf2_ims_mapping_output_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_IMS_MAPPING_OUTPUT, NULL);
}
