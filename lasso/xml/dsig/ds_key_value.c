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
#include "ds_key_value.h"

/**
 * SECTION:ds_key_value
 * @short_description: object mapping for an XML DSIG KeyValue element
 *
 */

struct _LassoDsKeyValuePrivate {
	LassoDsX509Data *X509Data;
};

typedef struct _LassoDsKeyValuePrivate LassoDsKeyValuePrivate;

#define LASSO_DS_KEY_VALUE_GET_PRIVATE(o) \
	   (G_TYPE_INSTANCE_GET_PRIVATE ((o), LASSO_TYPE_DS_KEY_VALUE, LassoDsKeyValuePrivate))

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{ "RSAKeyValue", SNIPPET_NODE, G_STRUCT_OFFSET(LassoDsKeyValue, RSAKeyValue), NULL, NULL, NULL},
	{ "X509Data", SNIPPET_NODE|SNIPPET_PRIVATE, G_STRUCT_OFFSET(LassoDsKeyValuePrivate, X509Data), NULL, NULL, NULL},
	{NULL, 0, 0, NULL, NULL, NULL}
};

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/


static void
class_init(LassoDsKeyValueClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "KeyValue");
	lasso_node_class_set_ns(nclass, LASSO_DS_HREF, LASSO_DS_PREFIX);
	lasso_node_class_add_snippets(nclass, schema_snippets);
	g_type_class_add_private(klass, sizeof(LassoDsKeyValuePrivate));
}

GType
lasso_ds_key_value_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoDsKeyValueClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoDsKeyValue),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_NODE,
				"LassoDsKeyValue", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_ds_key_value_new:
 *
 * Creates a new #LassoDsKeyValue object.
 *
 * Return value: a newly created #LassoDsKeyValue object
 **/
LassoDsKeyValue*
lasso_ds_key_value_new()
{
	return g_object_new(LASSO_TYPE_DS_KEY_VALUE, NULL);
}

/**
 * lasso_ds_key_value_get_x509_data:
 *
 * Get the X509 Data node if there is one.
 *
 * Return value:(transfer none): the internal value of the X509Data field
 */
LassoDsX509Data*
lasso_ds_key_value_get_x509_data(LassoDsKeyValue *key_value)
{
	lasso_return_val_if_fail(LASSO_IS_DS_KEY_VALUE(key_value), NULL);

	return LASSO_DS_KEY_VALUE_GET_PRIVATE(key_value)->X509Data;
}

/**
 * lasso_ds_key_value_set_x509_data:
 *
 * Set the X509 Data node.
 *
 */
void
lasso_ds_key_value_set_x509_data(LassoDsKeyValue *key_value, LassoDsX509Data *x509_data)
{
	lasso_return_if_fail(LASSO_IS_DS_KEY_VALUE(key_value));

	lasso_assign_gobject(LASSO_DS_KEY_VALUE_GET_PRIVATE(key_value)->X509Data, x509_data);
}
