/* $Id: is_interaction_statement.c,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include "is_interaction_statement.h"
#include "./idwsf2_strings.h"

/**
 * SECTION:is_interaction_statement
 * @short_description: &lt;is:InteractionStatement&gt;
 *
 * <figure><title>Schema fragment for is:InteractionStatement</title>
 * <programlisting><![CDATA[
 *
 * <xs:complexType name="InteractionStatementType">
 *   <xs:sequence>
 *     <xs:element ref="Inquiry" maxOccurs="unbounded"/>
 *     <xs:element ref="ds:Signature"/>
 *   </xs:sequence>
 * </xs:complexType>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/


static struct XmlSnippet schema_snippets[] = {
	{ "Inquiry", SNIPPET_LIST_NODES,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionStatement, Inquiry), NULL, NULL, NULL},
	{ "Signature", SNIPPET_SIGNATURE, 0, NULL, NULL, NULL  },

	/* hidden fields; used in lasso dumps */
	{ "SignType", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionStatement, sign_type), NULL, NULL, NULL},
	{ "SignMethod", SNIPPET_ATTRIBUTE | SNIPPET_INTEGER | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionStatement, sign_method), NULL, NULL, NULL},
	{ "PrivateKeyFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionStatement, private_key_file), NULL, NULL, NULL},
	{ "CertificateFile", SNIPPET_CONTENT | SNIPPET_LASSO_DUMP,
		G_STRUCT_OFFSET(LassoIdWsf2IsInteractionStatement, certificate_file), NULL, NULL, NULL},

	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;


/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoIdWsf2IsInteractionStatement *node)
{
	node->sign_type = LASSO_SIGNATURE_TYPE_NONE;
}

static void
class_init(LassoIdWsf2IsInteractionStatementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "InteractionStatement");
	lasso_node_class_set_ns(nclass, LASSO_IDWSF2_IS_HREF, LASSO_IDWSF2_IS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);

	nclass->node_data->sign_type_offset = G_STRUCT_OFFSET(
			LassoIdWsf2IsInteractionStatement, sign_type);
	nclass->node_data->sign_method_offset = G_STRUCT_OFFSET(
			LassoIdWsf2IsInteractionStatement, sign_method);
	nclass->node_data->private_key_file_offset = G_STRUCT_OFFSET(
			LassoIdWsf2IsInteractionStatement, private_key_file);
	nclass->node_data->certificate_file_offset = G_STRUCT_OFFSET(
			LassoIdWsf2IsInteractionStatement, certificate_file);
}

GType
lasso_idwsf2_is_interaction_statement_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoIdWsf2IsInteractionStatementClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoIdWsf2IsInteractionStatement),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoIdWsf2IsInteractionStatement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_idwsf2_is_interaction_statement_new:
 *
 * Creates a new #LassoIdWsf2IsInteractionStatement object.
 *
 * Return value: a newly created #LassoIdWsf2IsInteractionStatement object
 **/
LassoIdWsf2IsInteractionStatement*
lasso_idwsf2_is_interaction_statement_new()
{
	return g_object_new(LASSO_TYPE_IDWSF2_IS_INTERACTION_STATEMENT, NULL);
}
