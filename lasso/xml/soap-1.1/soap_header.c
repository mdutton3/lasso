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

#include "../private.h"
#include "soap_header.h"

/**
 * SECTION:soap_header
 * @short_description: &lt;soap:Header&gt;
 *
 */

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "any", SNIPPET_LIST_NODES | SNIPPET_ANY, G_STRUCT_OFFSET(LassoSoapHeader, Other), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoSoapHeaderClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Header");
	lasso_node_class_set_ns(nclass, LASSO_SOAP_ENV_HREF, LASSO_SOAP_ENV_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
}

GType
lasso_soap_header_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoSoapHeaderClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoSoapHeader),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoSoapHeader", &this_info, 0);
	}
	return this_type;
}

LassoSoapHeader*
lasso_soap_header_new()
{
	LassoSoapHeader *node;

	node = g_object_new(LASSO_TYPE_SOAP_HEADER, NULL);

	return node;
}

LassoSoapHeader*
lasso_soap_header_new_from_message(const gchar *message)
{
	LassoSoapHeader *node;

	g_return_val_if_fail(message != NULL, NULL);

	node = g_object_new(LASSO_TYPE_SOAP_HEADER, NULL);
	lasso_node_init_from_message(LASSO_NODE(node), message);

	return node;
}
