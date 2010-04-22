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

#include "../utils.h"
#include "private.h"
#include "samlp_status.h"

/**
 * SECTION:samlp_status
 * @short_description: &lt;samlp:Status&gt;
 *
 * <figure><title>Schema fragment for samlp:Status</title>
 * <programlisting><![CDATA[
 *
 * <element name="Status" type="samlp:StatusType"/>
 * <complexType name="StatusType">
 *   <sequence>
 *     <element ref="samlp:StatusCode"/>
 *     <element ref="samlp:StatusMessage" minOccurs="0" maxOccurs="1"/>
 *     <element ref="samlp:StatusDetail" minOccurs="0"/>
 *   </sequence>
 * </complexType>
 *
 * <element name="StatusMessage" type="string"/>
 * ]]></programlisting>
 * </figure>
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "StatusCode", SNIPPET_NODE, G_STRUCT_OFFSET(LassoSamlpStatus, StatusCode), NULL, NULL, NULL},
	{ "StatusMessage", SNIPPET_CONTENT, G_STRUCT_OFFSET(LassoSamlpStatus, StatusMessage), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

static gchar*
build_query(LassoNode *node)
{
	LassoSamlpStatusCode *code = LASSO_SAMLP_STATUS(node)->StatusCode;
	GString *s;
	char *t;

	s = g_string_sized_new(200);
	while (code) {
		if (s->len)
			g_string_append(s, " ");
		g_string_append(s, code->Value);
		code = code->StatusCode;
	}

	t = s->str;
	lasso_release_gstring(s, FALSE);
	return t;
}

static gboolean
init_from_query(LassoNode *node, char **query_fields)
{
	char **values;
	LassoSamlpStatusCode *code;
	int i;

	code = lasso_samlp_status_code_new();
	LASSO_SAMLP_STATUS(node)->StatusCode = code;
	values = g_strsplit(*query_fields, " ", 0);
	for (i = 0; values[i]; i++) {
		code->Value = g_strdup(values[i]);
		if (values[i+1]) {
			code->StatusCode = lasso_samlp_status_code_new();
			code = code->StatusCode;
		}
	}

	g_strfreev(values);
	return TRUE;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSamlpStatusClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->build_query = build_query;
	nclass->init_from_query = init_from_query;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Status");
	lasso_node_class_set_ns(nclass, LASSO_SAML_PROTOCOL_HREF, LASSO_SAML_PROTOCOL_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_samlp_status_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSamlpStatusClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSamlpStatus),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSamlpStatus", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_samlp_status_new:
 *
 * Creates a new #LassoSamlpStatus object.
 *
 * Return value: a newly created #LassoSamlpStatus object
 **/
LassoSamlpStatus*
lasso_samlp_status_new()
{
	return g_object_new(LASSO_TYPE_SAMLP_STATUS, NULL);
}
